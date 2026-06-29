"""Object detection, page classification, and text extraction (heuristic layer).

``ObjectDetector`` is the seam; the shipped :class:`HeuristicDetector` is
dependency-free — it infers visual elements (login form, search bar, buttons,
navigation, captcha, cookie banner, MFA, error message, popup) from the OCR
tokens and their boxes. A model-backed detector (YOLO, a layout model, or a
multimodal LLM) can implement the same interface later without touching callers.

Also here: :func:`classify_page` (what a screenshot depicts — login portal, admin
panel, dashboard, Swagger UI, GraphQL Playground, CMS, error/payment/API-docs
pages) and the text extractors (emails, phones, URLs, secrets) the OCR module
uses. Keeping this logic pure and import-light makes the whole layer testable
without any model download.
"""

from __future__ import annotations

import abc
import re

from recon_platform.vision.models import DetectedObject, OCRResult, PageClassification

# ---------------------------------------------------------------------------
# Element keyword heuristics (lowercased substring → element label)
# ---------------------------------------------------------------------------
_ELEMENT_KEYWORDS: dict[str, tuple[str, ...]] = {
    "login_form": ("log in", "login", "sign in", "username", "password", "log on"),
    "search_bar": ("search", "search here", "type to search"),
    "button": ("submit", "continue", "next", "sign up", "register", "get started", "ok"),
    "navigation": ("home", "about", "contact", "menu", "products", "services"),
    "captcha": ("captcha", "i'm not a robot", "recaptcha", "verify you are human"),
    "cookie_banner": ("accept cookies", "we use cookies", "cookie policy", "accept all"),
    "mfa": ("verification code", "one-time", "otp", "two-factor", "authenticator", "2fa"),
    "error_message": ("error", "not found", "forbidden", "access denied", "404", "500"),
    "popup": ("subscribe", "newsletter", "sign up for", "close", "no thanks"),
}

# ---------------------------------------------------------------------------
# Page classification signals (label → keywords)
# ---------------------------------------------------------------------------
_PAGE_SIGNALS: dict[str, tuple[str, ...]] = {
    "login_portal": ("log in", "login", "sign in", "password", "username", "forgot password"),
    "admin_panel": ("admin", "administration", "wp-admin", "control panel", "manage users"),
    "dashboard": ("dashboard", "overview", "analytics", "metrics", "welcome back"),
    "cms": ("wordpress", "drupal", "joomla", "wp-content", "powered by"),
    "error_page": ("404", "500", "not found", "forbidden", "internal server error"),
    "payment_page": ("payment", "checkout", "credit card", "cvv", "billing", "card number"),
    "api_docs": ("api documentation", "api reference", "endpoints", "authentication"),
    "swagger_ui": ("swagger", "openapi", "try it out", "swagger ui"),
    "graphql_playground": ("graphql", "playground", "query variables", "apollo"),
}

# ---------------------------------------------------------------------------
# Text extraction patterns
# ---------------------------------------------------------------------------
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
_PHONE_RE = re.compile(r"(?<!\d)(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?){2,4}\d{2,4}(?!\d)")
_URL_RE = re.compile(r"https?://[^\s\"'<>)]+", re.IGNORECASE)

# High-signal secret patterns (kind → regex).
_SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
    "github_token": re.compile(r"gh[pousr]_[0-9A-Za-z]{36}"),
    "slack_token": re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
}

# Hostnames / addresses that indicate internal infrastructure.
_INTERNAL_RE = re.compile(
    r"\b(?:localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
    r"[a-z0-9.-]+\.(?:internal|local|corp|intra|lan))\b",
    re.IGNORECASE,
)


class ObjectDetector(abc.ABC):
    """Abstract visual-element detector."""

    name: str = "detector"

    @property
    @abc.abstractmethod
    def available(self) -> bool:
        raise NotImplementedError

    @abc.abstractmethod
    async def detect(self, image_path: str, ocr: OCRResult) -> list[DetectedObject]:
        """Return detected elements (never raise; return [] on failure)."""
        raise NotImplementedError


class NullDetector(ObjectDetector):
    """Always-available no-op detector."""

    name = "null"

    @property
    def available(self) -> bool:
        return True

    async def detect(self, image_path: str, ocr: OCRResult) -> list[DetectedObject]:
        return []


class HeuristicDetector(ObjectDetector):
    """Dependency-free detector driven by OCR tokens.

    Each recognized token is matched against the element keyword table; a match
    yields a :class:`DetectedObject` carrying the token's box and confidence. This
    needs no model and is fully deterministic, which keeps the vision pipeline
    testable and useful even without the heavy ``vision`` extra installed.
    """

    name = "heuristic"

    @property
    def available(self) -> bool:
        return True

    async def detect(self, image_path: str, ocr: OCRResult) -> list[DetectedObject]:
        found: list[DetectedObject] = []
        seen: set[tuple[str, str]] = set()
        for token in ocr.tokens:
            text = token.text.lower().strip()
            if not text:
                continue
            for label, keywords in _ELEMENT_KEYWORDS.items():
                if any(kw in text for kw in keywords):
                    key = (label, text)
                    if key in seen:
                        continue
                    seen.add(key)
                    found.append(
                        DetectedObject(
                            label=label,
                            confidence=round(min(0.95, 0.5 + token.confidence / 2), 3),
                            box=token.box,
                            attributes={"text": token.text},
                        )
                    )
        return found


def build_detector(name: str) -> ObjectDetector:
    """Return a detector by name (``heuristic`` | ``null``)."""
    if name.lower() == "null":
        return NullDetector()
    return HeuristicDetector()


def classify_page(text: str) -> PageClassification:
    """Classify what a screenshot depicts from its OCR text (best single match)."""
    low = text.lower()
    best_label = "unknown"
    best_hits: list[str] = []
    for label, keywords in _PAGE_SIGNALS.items():
        hits = [kw for kw in keywords if kw in low]
        if len(hits) > len(best_hits):
            best_label, best_hits = label, hits
    if not best_hits:
        return PageClassification(page_type="unknown", confidence=0.0, signals=[])
    confidence = round(min(0.95, 0.4 + 0.18 * len(best_hits)), 3)
    return PageClassification(page_type=best_label, confidence=confidence, signals=best_hits)


def extract_emails(text: str) -> list[str]:
    return sorted({m.group(0).lower() for m in _EMAIL_RE.finditer(text)})


def extract_urls(text: str) -> list[str]:
    return sorted({m.group(0).rstrip(".,);") for m in _URL_RE.finditer(text)})


def extract_phones(text: str) -> list[str]:
    out: set[str] = set()
    for m in _PHONE_RE.finditer(text):
        raw = m.group(0).strip()
        digits = re.sub(r"\D", "", raw)
        # Require a plausible phone length to cut down on false positives.
        if 7 <= len(digits) <= 15:
            out.add(raw)
    return sorted(out)


def find_secrets(text: str) -> list[tuple[str, str]]:
    """Return ``(kind, value)`` pairs for high-signal secrets found in ``text``."""
    out: list[tuple[str, str]] = []
    for kind, pattern in _SECRET_PATTERNS.items():
        for m in pattern.finditer(text):
            out.append((kind, m.group(0)))
    return out


def extract_internal_urls(text: str) -> list[str]:
    return sorted({m.group(0).lower() for m in _INTERNAL_RE.finditer(text)})
