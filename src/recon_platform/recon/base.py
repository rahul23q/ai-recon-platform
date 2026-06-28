"""Base abstractions for recon modules.

A `ReconModule` is the smallest unit of discovery. It receives a `ModuleContext`
(shared HTTP client + settings + the normalized target) and returns a
`ReconResult`. Modules must be side-effect-light and resilient: failures are
captured in ``result.errors`` rather than raised, so one failing module never
aborts a run.
"""

from __future__ import annotations

import abc

import httpx

from recon_platform.core.config import Settings
from recon_platform.domain.enums import ToolPermission
from recon_platform.domain.schemas import ReconResult


class ModuleContext:
    """Shared resources handed to every module during a run."""

    def __init__(self, target: str, http: httpx.AsyncClient, settings: Settings) -> None:
        self.target = target
        self.http = http
        self.settings = settings


class ReconModule(abc.ABC):
    """Abstract base for a passive recon capability."""

    #: Stable identifier used in results and reports.
    name: str = "module"
    #: Human description.
    description: str = ""
    #: Capabilities required; passive modules only declare NETWORK_PASSIVE.
    permissions: tuple[ToolPermission, ...] = (ToolPermission.NETWORK_PASSIVE,)

    @abc.abstractmethod
    async def run(self, ctx: ModuleContext) -> ReconResult:
        """Execute the module and return a ReconResult (never raise for I/O)."""
        raise NotImplementedError

    def _empty(self) -> ReconResult:
        return ReconResult(task_id="", module=self.name)
