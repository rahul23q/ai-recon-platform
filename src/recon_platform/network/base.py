"""Base abstractions for network modules.

Mirrors :mod:`recon_platform.vision.base`: a ``NetworkModule`` is the smallest
unit of network-observation analysis. It receives a :class:`NetworkContext` — a
read-only snapshot of the relevant assets the agent gathered from the knowledge
graph (headers, cookies, tokens, endpoints) plus settings and a shared cache —
and returns a :class:`~recon_platform.domain.schemas.ReconResult` of new
network-layer assets/relations.

Like every other module family, network modules must be resilient: analysis
errors are captured in ``result.errors`` rather than raised, so one failing
module never aborts a run. Modules never issue network I/O — they only reason
over what earlier agents already observed.
"""

from __future__ import annotations

import abc
from typing import Any

from recon_platform.core.config import Settings
from recon_platform.domain.enums import ToolPermission
from recon_platform.domain.schemas import Asset, ReconResult


class NetworkContext:
    """A read-only snapshot of network-relevant assets handed to every module.

    The agent populates the asset lists from the knowledge graph so modules stay
    graph-free and trivially testable. ``_cache`` is the same side-channel the
    other contexts use for cross-module state.
    """

    def __init__(
        self,
        target: str,
        settings: Settings,
        *,
        headers: list[Asset] | None = None,
        cookies: list[Asset] | None = None,
        tokens: list[Asset] | None = None,
        endpoints: list[Asset] | None = None,
    ) -> None:
        self.target = target
        self.settings = settings
        self.headers: list[Asset] = list(headers or [])
        self.cookies: list[Asset] = list(cookies or [])
        self.tokens: list[Asset] = list(tokens or [])
        self.endpoints: list[Asset] = list(endpoints or [])
        self._cache: dict[str, Any] = {}


class NetworkModule(abc.ABC):
    """Abstract base for a network-analysis capability."""

    #: Stable identifier used in results and reports.
    name: str = "network_module"
    #: Human description.
    description: str = ""
    #: Passive analysis over already-captured data; no new network I/O.
    permissions: tuple[ToolPermission, ...] = (ToolPermission.NETWORK_PASSIVE,)

    @abc.abstractmethod
    async def run(self, ctx: NetworkContext) -> ReconResult:
        """Execute the module and return a ReconResult (never raise for errors)."""
        raise NotImplementedError

    def _empty(self) -> ReconResult:
        return ReconResult(task_id="", module=self.name)
