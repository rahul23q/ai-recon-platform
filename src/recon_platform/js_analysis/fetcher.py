"""GET-only fetch helper for the JS-analysis agent.

Isolated here (rather than inline in the agent) so the network boundary is a
single, easily-mocked seam: the hermetic tests patch
``recon_platform.agents.js_analysis.fetch_js`` to return canned bodies, and the
agent itself never imports a real client in tests. The fetch is strictly GET,
size-capped, and failure-tolerant (returns ``None`` instead of raising), matching
the passive posture of the recon modules.
"""

from __future__ import annotations

import httpx

from recon_platform.core.logging import get_logger

log = get_logger(__name__)


async def fetch_js(
    client: httpx.AsyncClient, url: str, *, max_bytes: int = 2_000_000
) -> str | None:
    """GET a script body, capped at ``max_bytes``. Returns ``None`` on any error.

    Non-2xx responses and oversized/binary bodies yield ``None`` so a bad URL
    never aborts the run; callers record a note and move on.
    """
    try:
        resp = await client.get(url)
    except Exception as exc:  # noqa: BLE001 - passive fetch must never raise
        log.info("js.fetch.error", url=url, error=str(exc))
        return None
    if resp.status_code >= 400:
        return None
    text = resp.text or ""
    if max_bytes and len(text) > max_bytes:
        return text[:max_bytes]
    return text
