"""Pure, dependency-free JavaScript-analysis helpers.

These functions carry all the extraction logic (endpoints, request parameters,
source-map references) so it is deterministic and directly unit-testable without a
network or any I/O. Secret detection reuses the shared high-signal patterns from
:func:`recon_platform.vision.detector.find_secrets` so JS and OCR report secrets
identically. The modules in :mod:`recon_platform.js_analysis.modules` are thin
wrappers that apply these to the script bodies the agent fetched.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

# Absolute URLs and root/relative API-ish paths embedded in string literals.
_ABS_URL_RE = re.compile(r"""https?://[^\s"'`<>()\\]+""", re.IGNORECASE)
# Quoted path literals: "/api/v1/x", '/users/1?y=1', `/graphql` — must start with
# a single slash (not "//" protocol-relative noise) and run to the closing quote
# (so query strings are captured); whitespace/quotes/angle-brackets end the match.
_PATH_RE = re.compile(r"""["'`](/[A-Za-z0-9_][^\s"'`<>]*)["'`]""")
# sourceMappingURL comment (JS or CSS style) and inline data maps are ignored.
_SOURCEMAP_RE = re.compile(
    r"""(?://[#@]|/\*[#@])\s*sourceMappingURL\s*=\s*([^\s*'"]+)""", re.IGNORECASE
)

# Paths that are almost certainly static assets, not endpoints — filtered out to
# keep the endpoint surface signal-heavy.
_STATIC_SUFFIXES = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff",
    ".woff2", ".ttf", ".eot", ".map", ".webp", ".mp4", ".mp3",
)


def _looks_static(path: str) -> bool:
    clean = path.split("?", 1)[0].split("#", 1)[0].lower()
    return clean.endswith(_STATIC_SUFFIXES)


def extract_endpoints(js: str, *, base_url: str = "") -> list[str]:
    """Extract distinct endpoint URLs/paths referenced in a script body.

    Absolute URLs are returned as-is; root-relative paths are resolved against
    ``base_url`` when given (else returned as the bare path). Obvious static-asset
    references are dropped. Order-preserving and de-duplicated.
    """
    seen: list[str] = []
    out: set[str] = set()

    def add(value: str) -> None:
        if value and value not in out:
            out.add(value)
            seen.append(value)

    for m in _ABS_URL_RE.findall(js or ""):
        url = m.rstrip(".,);")
        if not _looks_static(url):
            add(url)
    for m in _PATH_RE.findall(js or ""):
        if _looks_static(m):
            continue
        add(urljoin(base_url, m) if base_url else m)
    return seen


def extract_parameters(js: str, *, base_url: str = "") -> list[dict]:
    """Extract query-parameter names from URL/path literals in a script body."""
    out: list[dict] = []
    seen: set[str] = set()
    for endpoint in extract_endpoints(js, base_url=base_url):
        query = urlsplit(endpoint).query
        if not query:
            continue
        for pair in query.split("&"):
            name = pair.split("=", 1)[0]
            if name and name not in seen:
                seen.add(name)
                out.append({"name": name, "location": "query"})
    return out


def find_source_maps(js: str, *, base_url: str = "") -> list[str]:
    """Return source-map references (``sourceMappingURL``) found in a script.

    Data-URI inline maps are skipped (nothing to fetch); file references are
    resolved against ``base_url`` when provided.
    """
    out: list[str] = []
    seen: set[str] = set()
    for ref in _SOURCEMAP_RE.findall(js or ""):
        if ref.lower().startswith("data:"):
            continue
        resolved = urljoin(base_url, ref) if base_url else ref
        if resolved not in seen:
            seen.add(resolved)
            out.append(resolved)
    return out


def is_internal_url(url: str, target: str) -> bool:
    """True when ``url``'s host is the target host or a subdomain of it."""
    host = urlsplit(url).netloc.split("@")[-1].split(":")[0].lower()
    t = (target or "").lower().lstrip(".")
    if not host or not t:
        return False
    return host == t or host.endswith("." + t)
