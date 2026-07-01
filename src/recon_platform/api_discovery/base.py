"""Base abstractions for API-discovery modules.

Mirrors :mod:`recon_platform.network.base`: an ``APIModule`` is the smallest unit
of API characterization. It receives an :class:`APIDiscoveryContext` — a
read-only snapshot of the relevant assets the agent gathered from the knowledge
graph (endpoints/URLs, headers, JS files, and the Network agent's classified
``API_ENDPOINT`` assets) plus settings and a shared cache — and returns a
:class:`~recon_platform.domain.schemas.ReconResult` of new API-layer
assets/relations.

Like every other module family, API modules must be resilient: analysis errors
are captured in ``result.errors`` rather than raised, so one failing module never
aborts a run. Modules never issue network I/O — they only reason over what earlier
agents already observed.
"""

from __future__ import annotations

import abc
from typing import Any

from recon_platform.core.config import Settings
from recon_platform.domain.enums import ToolPermission
from recon_platform.domain.schemas import Asset, ReconResult


class APIDiscoveryContext:
    """A read-only snapshot of API-relevant assets handed to every module.

    The agent populates the asset lists from the knowledge graph so modules stay
    graph-free and trivially testable. ``_cache`` is the same side-channel the
    other contexts use for cross-module state.
    """

    def __init__(
        self,
        target: str,
        settings: Settings,
        *,
        endpoints: list[Asset] | None = None,
        headers: list[Asset] | None = None,
        js_files: list[Asset] | None = None,
        api_endpoints: list[Asset] | None = None,
    ) -> None:
        self.target = target
        self.settings = settings
        self.endpoints: list[Asset] = list(endpoints or [])
        self.headers: list[Asset] = list(headers or [])
        self.js_files: list[Asset] = list(js_files or [])
        self.api_endpoints: list[Asset] = list(api_endpoints or [])
        self._cache: dict[str, Any] = {}


class APIModule(abc.ABC):
    """Abstract base for an API-discovery capability."""

    #: Stable identifier used in results and reports.
    name: str = "api_module"
    #: Human description.
    description: str = ""
    #: Passive analysis over already-captured data; no new network I/O.
    permissions: tuple[ToolPermission, ...] = (ToolPermission.NETWORK_PASSIVE,)

    @abc.abstractmethod
    async def run(self, ctx: APIDiscoveryContext) -> ReconResult:
        """Execute the module and return a ReconResult (never raise for errors)."""
        raise NotImplementedError

    def _empty(self) -> ReconResult:
        return ReconResult(task_id="", module=self.name)
