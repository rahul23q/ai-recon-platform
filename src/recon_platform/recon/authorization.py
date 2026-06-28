"""Target authorization gate.

The platform is for *authorized* testing only. This is a defensive guardrail,
not a license: it prevents accidental scans of out-of-scope hosts. When an
explicit allowlist is configured, the target must match it.
"""

from __future__ import annotations

from recon_platform.core.config import Settings
from recon_platform.core.exceptions import UnauthorizedTargetError


def normalize_target(target: str) -> str:
    """Reduce a URL/host to a bare hostname for comparison."""
    t = target.strip().lower()
    for prefix in ("https://", "http://"):
        if t.startswith(prefix):
            t = t[len(prefix) :]
    t = t.split("/", 1)[0].split(":", 1)[0]
    return t


def ensure_authorized(target: str, settings: Settings) -> str:
    """Validate a target against the engagement policy; return the normalized host.

    Raises UnauthorizedTargetError when policy denies the target.
    """
    host = normalize_target(target)
    if not host:
        raise UnauthorizedTargetError("Empty target.")

    if not settings.authorized_only:
        return host

    allowlist = [normalize_target(t) for t in settings.authorized_targets]
    if not allowlist:
        # No explicit allowlist: permitted, but the operator is responsible for
        # scope. Active modules should still require an explicit opt-in.
        return host

    for allowed in allowlist:
        if host == allowed or host.endswith("." + allowed):
            return host

    raise UnauthorizedTargetError(
        f"Target {host!r} is not in the authorized allowlist. "
        "Add it to RECON_AUTHORIZED_TARGETS or disable RECON_AUTHORIZED_ONLY."
    )
