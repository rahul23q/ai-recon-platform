"""Pure cross-source security-header verification.

Two responsibilities, both free of I/O so they are trivially testable:

* :func:`collect_header_maps` — read the knowledge graph's ``HEADER`` assets and
  split them into the passive-HTTP view and the in-browser view, **normalizing
  every header name to lowercase** so comparison is case-insensitive.
* :func:`compute_header_verifications` — compare the two views against the
  required security-header set and emit a :class:`Verification` per header.

The verdict matrix (passive ``p`` vs browser ``b`` presence) is the heart of the
false-positive fix:

| passive | browser | observed-by-browser | verdict (claim)                    |
|:-------:|:-------:|:-------------------:|------------------------------------|
|   ✕     |   ✕     |        yes          | VERIFIED (missing)                 |
|   ✓     |   ✓     |        yes          | VERIFIED (present)                 |
|   ✕     |   ✓     |        yes          | FALSE_POSITIVE (missing claim)     |
|   ✓     |   ✕     |        yes          | NEEDS_VERIFICATION (present claim) |
|   ✕     |   —     |        no           | LIKELY (missing)                   |
|   ✓     |   —     |        no           | LIKELY (present)                   |
"""

from __future__ import annotations

from recon_platform.domain.enums import AssetType, VerificationStatus
from recon_platform.domain.interfaces import KnowledgeGraph
from recon_platform.domain.schemas import Verification
from recon_platform.recon.modules import SECURITY_HEADERS

#: Source tags recorded on verifications.
SOURCE_PASSIVE = "passive-http"
SOURCE_BROWSER = "browser"

#: Asset ``source`` values that identify each observer's HEADER assets.
_PASSIVE_SOURCES = {"http_headers"}
_BROWSER_SOURCES = {"network_capture"}


def collect_header_maps(
    graph: KnowledgeGraph,
) -> tuple[dict[str, str], dict[str, str], bool]:
    """Return ``(passive, browser, browser_observed)`` header maps.

    Keys are lowercased header names; values are the header values. Headers are
    case-insensitive per RFC 9110, so normalization here removes any chance of a
    casing mismatch producing a spurious "missing" result. ``browser_observed``
    is True when the Browser agent captured *any* response headers — only then
    can the browser corroborate or refute the passive view.
    """
    passive: dict[str, str] = {}
    browser: dict[str, str] = {}
    for asset in graph.assets(AssetType.HEADER):
        name = str(asset.attributes.get("name", "")).strip().lower()
        if not name:
            continue
        value = str(asset.attributes.get("value", ""))
        if asset.source in _PASSIVE_SOURCES:
            passive.setdefault(name, value)
        elif asset.source in _BROWSER_SOURCES:
            browser.setdefault(name, value)
    return passive, browser, bool(browser)


def compute_header_verifications(
    passive: dict[str, str],
    browser: dict[str, str],
    browser_observed: bool,
) -> list[Verification]:
    """Emit a :class:`Verification` per required security header.

    Inputs are normalized defensively (lowercased) so the function is correct even
    if a caller passes raw header names.
    """
    passive = {k.lower(): v for k, v in passive.items()}
    browser = {k.lower(): v for k, v in browser.items()}

    results: list[Verification] = []
    for header in SECURITY_HEADERS:
        p = header in passive
        if browser_observed:
            b = header in browser
            sources = [SOURCE_PASSIVE, SOURCE_BROWSER]
            if p and b:
                v = Verification(
                    subject=f"security-header:{header}",
                    claim="present",
                    status=VerificationStatus.VERIFIED,
                    confidence=0.95,
                    sources=sources,
                    detail="present in both passive HTTP and browser responses",
                )
            elif not p and not b:
                v = Verification(
                    subject=f"security-header:{header}",
                    claim="missing",
                    status=VerificationStatus.VERIFIED,
                    confidence=0.9,
                    sources=sources,
                    detail="absent from both passive HTTP and browser responses",
                )
            elif not p and b:
                # The passive "missing" claim is contradicted by the browser —
                # exactly the CSP-style false positive we are eliminating.
                v = Verification(
                    subject=f"security-header:{header}",
                    claim="missing",
                    status=VerificationStatus.FALSE_POSITIVE,
                    confidence=0.2,
                    sources=sources,
                    detail=(
                        "reported missing by passive HTTP but observed in the "
                        "browser response (server likely sends it only to browsers)"
                    ),
                )
            else:  # p and not b
                v = Verification(
                    subject=f"security-header:{header}",
                    claim="present",
                    status=VerificationStatus.NEEDS_VERIFICATION,
                    confidence=0.5,
                    sources=sources,
                    detail="seen by passive HTTP but not in the browser response",
                )
        else:
            v = Verification(
                subject=f"security-header:{header}",
                claim="present" if p else "missing",
                status=VerificationStatus.LIKELY,
                confidence=0.8,
                sources=[SOURCE_PASSIVE],
                detail="single-source passive HTTP observation (browser not run)",
            )
        results.append(v)
    return results
