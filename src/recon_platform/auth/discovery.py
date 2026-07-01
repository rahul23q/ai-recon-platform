"""Pure candidate-URL discovery for the authentication workflows.

Selects likely login / registration / forgot-password / admin URLs from the
``URL`` and ``ENDPOINT`` assets other agents already put in the knowledge graph
(and any explicit override in settings). Deterministic and dependency-free.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from recon_platform.domain.schemas import Asset

_LOGIN_HINTS = ("/login", "/signin", "/sign-in", "/log-in", "/auth", "/account/login", "/session")
_REGISTER_HINTS = ("/register", "/signup", "/sign-up", "/join", "/account/create", "/registration")
_FORGOT_HINTS = ("/forgot", "/reset", "/password/reset", "/recover", "/forgot-password")
_ADMIN_HINTS = ("/admin", "/administrator", "/wp-admin", "/manage", "/dashboard", "/cpanel")


def _match(assets: list[Asset], hints: tuple[str, ...], limit: int) -> list[str]:
    """Return distinct http(s) URLs whose path contains any hint (order-preserving)."""
    out: list[str] = []
    seen: set[str] = set()
    for asset in assets:
        url = asset.value
        if not url.lower().startswith(("http://", "https://")):
            continue
        path = urlsplit(url).path.lower()
        if any(h in path for h in hints) and url not in seen:
            seen.add(url)
            out.append(url)
            if len(out) >= limit:
                break
    return out


def candidate_login_urls(assets: list[Asset], *, explicit: str = "", limit: int = 5) -> list[str]:
    urls = [explicit] if explicit else []
    for u in _match(assets, _LOGIN_HINTS, limit):
        if u not in urls:
            urls.append(u)
    return urls[:limit]


def candidate_register_urls(
    assets: list[Asset], *, explicit: str = "", limit: int = 5
) -> list[str]:
    urls = [explicit] if explicit else []
    for u in _match(assets, _REGISTER_HINTS, limit):
        if u not in urls:
            urls.append(u)
    return urls[:limit]


def candidate_forgot_urls(assets: list[Asset], *, limit: int = 5) -> list[str]:
    return _match(assets, _FORGOT_HINTS, limit)


def candidate_admin_urls(assets: list[Asset], *, limit: int = 5) -> list[str]:
    return _match(assets, _ADMIN_HINTS, limit)
