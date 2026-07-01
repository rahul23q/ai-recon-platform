"""Pure, dependency-free network detection helpers.

These functions carry all the analysis logic (JWT decoding, endpoint
classification, CORS checks, WebSocket detection) so it is deterministic and
directly unit-testable without a graph, a network, or any I/O. The modules in
:mod:`recon_platform.network.modules` are thin wrappers that apply these to the
assets the agent snapshots from the knowledge graph.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import time
from dataclasses import dataclass, field

# A JWT is three base64url segments joined by dots; the header/payload start with
# ``eyJ`` (base64url of ``{"``). We match compact JWS tokens embedded in text.
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}")

# Claims whose presence in a token payload is worth calling out (PII / privilege).
_SENSITIVE_CLAIMS = {"email", "role", "roles", "admin", "is_admin", "groups", "scope", "password"}

# Weak / dangerous JWS algorithms.
_WEAK_ALGS = {"none", "hs256"}  # HS256 flagged only informationally (see issues)


@dataclass
class DecodedJWT:
    """A decoded (unverified) JSON Web Token and any weaknesses found."""

    raw: str
    alg: str = ""
    typ: str = ""
    header: dict = field(default_factory=dict)
    payload: dict = field(default_factory=dict)
    issues: list[str] = field(default_factory=list)

    @property
    def masked(self) -> str:
        """A short, non-sensitive identifier for evidence."""
        if len(self.raw) <= 16:
            return "•" * len(self.raw)
        return f"{self.raw[:8]}…{self.raw[-6:]} ({len(self.raw)} chars)"


def _b64url_decode(segment: str) -> bytes:
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


def decode_jwt(token: str, *, now: float | None = None) -> DecodedJWT | None:
    """Decode a compact JWS token's header + payload and flag weaknesses.

    Returns ``None`` if the string is not a decodable JWT. The signature is never
    checked — this is inspection, not validation. ``now`` (epoch seconds) can be
    injected for deterministic expiry checks in tests.
    """
    token = token.strip()
    parts = token.split(".")
    if len(parts) != 3 or not token.startswith("eyJ"):
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None

    alg = str(header.get("alg", "")).strip()
    typ = str(header.get("typ", "")).strip()
    decoded = DecodedJWT(raw=token, alg=alg, typ=typ, header=header, payload=payload)

    issues: list[str] = []
    if alg.lower() == "none":
        issues.append("alg=none (unsigned token accepted → forgeable)")
    elif alg.lower() in _WEAK_ALGS:
        issues.append(f"symmetric alg {alg} (verify secret strength / key confusion risk)")
    if "exp" not in payload:
        issues.append("no 'exp' claim (token never expires)")
    else:
        try:
            exp = float(payload["exp"])
            current = time.time() if now is None else now
            if exp < current:
                issues.append("expired (exp in the past)")
        except (TypeError, ValueError):
            issues.append("malformed 'exp' claim")
    sensitive = sorted(_SENSITIVE_CLAIMS & {str(k).lower() for k in payload})
    if sensitive:
        issues.append("carries sensitive claim(s): " + ", ".join(sensitive))
    decoded.issues = issues
    return decoded


def find_jwts(text: str) -> list[str]:
    """Return all distinct JWT-looking substrings in ``text`` (order-preserving)."""
    seen: list[str] = []
    for m in JWT_RE.findall(text or ""):
        if m not in seen:
            seen.append(m)
    return seen


def classify_api_endpoint(url: str) -> str | None:
    """Classify a URL as ``graphql`` or ``rest`` traffic, or ``None`` if neither."""
    u = url.lower()
    path = u.split("?", 1)[0]
    if any(seg in path for seg in ("/graphql", "/graphiql", "/gql")):
        return "graphql"
    if (
        "/api/" in path
        or path.endswith("/api")
        or path.endswith(".json")
        or re.search(r"/v\d+(/|$)", path)
        or "/rest/" in path
        or "/wp-json" in path
    ):
        return "rest"
    return None


def websocket_endpoints(text: str) -> list[tuple[str, bool]]:
    """Return ``(url, secure)`` for each ws:// / wss:// URL found in ``text``."""
    out: list[tuple[str, bool]] = []
    for m in re.findall(r"wss?://[^\s\"'<>()]+", text or "", flags=re.IGNORECASE):
        secure = m.lower().startswith("wss://")
        pair = (m, secure)
        if pair not in out:
            out.append(pair)
    return out


def cors_issues(header_name: str, header_value: str, *, credentialed: bool) -> list[str]:
    """Flag dangerous CORS configuration for one response header.

    ``credentialed`` is True when ``Access-Control-Allow-Credentials: true`` was
    also observed on the response — the combination with a wildcard/reflected
    origin is the dangerous case.
    """
    name = header_name.strip().lower()
    value = header_value.strip()
    if name != "access-control-allow-origin":
        return []
    issues: list[str] = []
    if value == "*":
        if credentialed:
            issues.append(
                "Access-Control-Allow-Origin: * with credentials — any origin can "
                "read authenticated responses"
            )
        else:
            issues.append("Access-Control-Allow-Origin: * (open CORS)")
    elif value.lower() == "null":
        issues.append("Access-Control-Allow-Origin: null (bypassable via sandboxed origins)")
    return issues
