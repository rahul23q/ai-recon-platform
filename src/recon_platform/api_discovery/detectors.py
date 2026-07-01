"""Pure, dependency-free API-discovery detection helpers.

These functions carry all the characterization logic (API-style classification,
REST resource/version parsing, request-parameter extraction, auth-scheme
detection, OpenAPI parsing) so it is deterministic and directly unit-testable
without a graph, a network, or any I/O. The modules in
:mod:`recon_platform.api_discovery.modules` are thin wrappers that apply these to
the assets the agent snapshots from the knowledge graph.
"""

from __future__ import annotations

import json
import re
from urllib.parse import parse_qsl, urlsplit

# A path segment that looks like an identifier rather than a resource name:
# all-digits, a UUID, or a long hex/opaque token.
_NUMERIC_RE = re.compile(r"^\d+$")
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_HEX_RE = re.compile(r"^[0-9a-f]{16,}$", re.I)
_VERSION_RE = re.compile(r"^v\d+$", re.I)


def _is_param_segment(seg: str) -> bool:
    """True when a path segment looks like an identifier value, not a resource."""
    s = seg.strip()
    return bool(_NUMERIC_RE.match(s) or _UUID_RE.match(s) or _HEX_RE.match(s))


def api_style(url: str) -> str | None:
    """Classify a URL as ``graphql`` / ``soap`` / ``grpc`` / ``rest`` traffic.

    Returns ``None`` when the URL does not look like an API endpoint. GraphQL,
    SOAP, and gRPC are checked before the broad REST heuristics so a more specific
    style always wins.
    """
    parts = urlsplit(url.lower())
    path = parts.path
    query = parts.query
    if any(seg in path for seg in ("/graphql", "/graphiql", "/gql")):
        return "graphql"
    if path.endswith((".asmx", ".svc")) or "wsdl" in query or "/soap" in path:
        return "soap"
    if "/grpc" in path or path.endswith(".proto") or "grpc-web" in path:
        return "grpc"
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


def rest_signature(url: str) -> dict | None:
    """Infer a REST API's base path, version, and leading resource from a URL.

    Anchors on an explicit ``/vN`` version segment when present, otherwise on an
    ``/api`` segment. Returns ``None`` when neither anchor is found (so plain
    ``.json`` links don't fabricate a REST API).
    """
    parts = urlsplit(url)
    segs = [s for s in parts.path.split("/") if s]
    lowered = [s.lower() for s in segs]

    anchor = -1
    version = ""
    for i, s in enumerate(lowered):
        if _VERSION_RE.match(s):
            anchor = i
            version = s
            break
    if anchor == -1 and "api" in lowered:
        anchor = lowered.index("api")

    if anchor == -1:
        return None

    base_path = "/" + "/".join(segs[: anchor + 1])
    resource = segs[anchor + 1] if anchor + 1 < len(segs) else ""
    if _is_param_segment(resource):
        resource = ""
    return {
        "host": parts.netloc,
        "base_path": base_path,
        "version": version,
        "resource": resource,
    }


def extract_parameters(url: str) -> list[dict]:
    """Extract request parameters (query + identifier-style path segments)."""
    parts = urlsplit(url)
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()

    for name, value in parse_qsl(parts.query):
        key = ("query", name)
        if name and key not in seen:
            seen.add(key)
            out.append({"name": name, "location": "query", "example": value})

    segs = [s for s in parts.path.split("/") if s]
    for i, seg in enumerate(segs):
        if not _is_param_segment(seg):
            continue
        prev = segs[i - 1] if i > 0 else ""
        pname = (prev.rstrip("s") + "_id") if prev and not _is_param_segment(prev) else "id"
        key = ("path", pname)
        if key not in seen:
            seen.add(key)
            out.append({"name": pname, "location": "path", "example": seg})
    return out


def detect_auth_schemes(headers: list[tuple[str, str]]) -> list[dict]:
    """Detect authentication schemes from request/response header pairs.

    ``headers`` is a list of ``(name, value)`` pairs (case-insensitive names).
    Returns a distinct, order-preserving list of ``{"scheme", "detail"}`` dicts.
    """
    schemes: list[dict] = []
    seen: set[str] = set()

    def add(scheme: str, detail: str = "") -> None:
        if scheme not in seen:
            seen.add(scheme)
            schemes.append({"scheme": scheme, "detail": detail})

    for raw_name, raw_value in headers:
        name = (raw_name or "").strip().lower()
        value = (raw_value or "").strip()
        low = value.lower()
        if name == "authorization":
            if low.startswith("bearer "):
                add("bearer", "Authorization: Bearer")
            elif low.startswith("basic "):
                add("basic", "Authorization: Basic")
            elif low.startswith("digest "):
                add("digest", "Authorization: Digest")
            elif value:
                add("custom", f"Authorization: {value.split(' ', 1)[0]}")
        elif name == "www-authenticate" and value:
            scheme = value.split(" ", 1)[0].lower()
            if scheme in ("basic", "bearer", "digest", "negotiate", "ntlm"):
                add(scheme, f"WWW-Authenticate: {scheme}")
        elif name in ("x-api-key", "api-key", "apikey", "x-apikey"):
            add("api_key", f"{name} header")
        elif name in ("set-cookie", "cookie") and value:
            add("cookie", "cookie-based session")
    return schemes


def parse_openapi(text: str) -> dict | None:
    """Parse an OpenAPI / Swagger document, returning its title/version/paths.

    Returns ``None`` when the text is not a recognizable OpenAPI/Swagger spec.
    """
    try:
        doc = json.loads(text)
    except (ValueError, TypeError):
        return None
    if not isinstance(doc, dict) or not ("openapi" in doc or "swagger" in doc):
        return None
    info = doc.get("info") if isinstance(doc.get("info"), dict) else {}
    paths = doc.get("paths") if isinstance(doc.get("paths"), dict) else {}
    return {
        "title": str(info.get("title", "")),
        "version": str(info.get("version", "")),
        "spec": str(doc.get("openapi") or doc.get("swagger") or ""),
        "paths": sorted(str(p) for p in paths)[:200],
    }
