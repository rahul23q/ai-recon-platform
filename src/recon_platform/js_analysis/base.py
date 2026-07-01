"""Base abstractions for JavaScript-analysis modules.

A ``JSModule`` is the smallest unit of client-side analysis. It receives a
:class:`JSContext` — the target, settings, and a ``{url: source}`` map of the
script bodies the agent already fetched — and returns a
:class:`~recon_platform.domain.schemas.ReconResult` of new assets/relations.

Modules never perform I/O themselves (the agent does the GET-only fetching); they
only reason over the fetched text. Like every other module family they must be
resilient: analysis errors are captured in ``result.errors`` rather than raised,
so one failing module never aborts a run.
"""

from __future__ import annotations

import abc
from typing import Any

from recon_platform.core.config import Settings
from recon_platform.domain.enums import ToolPermission
from recon_platform.domain.schemas import ReconResult


class JSContext:
    """Snapshot handed to every JS module: the fetched script bodies + settings.

    ``sources`` maps a script URL to its text. ``_cache`` is the same side-channel
    the other contexts use for cross-module state.
    """

    def __init__(
        self,
        target: str,
        settings: Settings,
        *,
        sources: dict[str, str] | None = None,
    ) -> None:
        self.target = target
        self.settings = settings
        self.sources: dict[str, str] = dict(sources or {})
        self._cache: dict[str, Any] = {}


class JSModule(abc.ABC):
    """Abstract base for a JavaScript-analysis capability."""

    #: Stable identifier used in results and reports.
    name: str = "js_module"
    #: Human description.
    description: str = ""
    #: Passive analysis over already-fetched script text; no new I/O here.
    permissions: tuple[ToolPermission, ...] = (ToolPermission.NETWORK_PASSIVE,)

    @abc.abstractmethod
    async def run(self, ctx: JSContext) -> ReconResult:
        """Execute the module and return a ReconResult (never raise for errors)."""
        raise NotImplementedError

    def _empty(self) -> ReconResult:
        return ReconResult(task_id="", module=self.name)
