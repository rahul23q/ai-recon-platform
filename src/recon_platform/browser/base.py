"""Base abstractions for browser modules.

Mirrors :mod:`recon_platform.recon.base`: a ``BrowserModule`` is the smallest unit
of in-browser observation. It receives a :class:`BrowserContext` (the live
Playwright ``Page``, the normalized target, settings, and a shared ``_cache`` for
cross-module page state) and returns a :class:`~recon_platform.domain.schemas.ReconResult`.

Like recon modules, browser modules must be resilient: I/O failures are captured
in ``result.errors`` rather than raised, so one failing module never aborts a run.
"""

from __future__ import annotations

import abc
from typing import Any

from recon_platform.core.config import Settings
from recon_platform.domain.enums import ToolPermission
from recon_platform.domain.schemas import ReconResult


class BrowserContext:
    """Shared resources handed to every browser module during a run.

    ``session`` is the live :class:`~recon_platform.browser.session.BrowserSession`
    (typed ``Any`` so this module never imports Playwright). It drives navigation
    and exposes the captured network traffic, cookies, and screenshot helper;
    ``page`` is a convenience alias for ``session.page`` used by DOM-reading
    modules. ``_cache`` is the same side-channel pattern used by the recon
    :class:`~recon_platform.recon.base.ModuleContext`: earlier modules stash
    observations (e.g. the final navigated URL) that later modules read.
    """

    def __init__(self, target: str, session: Any, settings: Settings) -> None:
        self.target = target
        self.session = session
        self.settings = settings
        self._cache: dict[str, Any] = {}

    @property
    def page(self) -> Any:
        """The live Playwright ``Page`` (or None before navigation)."""
        return getattr(self.session, "page", None)


class BrowserModule(abc.ABC):
    """Abstract base for an in-browser observation capability."""

    #: Stable identifier used in results and reports.
    name: str = "browser_module"
    #: Human description.
    description: str = ""
    #: Capabilities required; browser modules drive a real browser.
    permissions: tuple[ToolPermission, ...] = (ToolPermission.BROWSER,)

    @abc.abstractmethod
    async def run(self, ctx: BrowserContext) -> ReconResult:
        """Execute the module and return a ReconResult (never raise for I/O)."""
        raise NotImplementedError

    def _empty(self) -> ReconResult:
        return ReconResult(task_id="", module=self.name)
