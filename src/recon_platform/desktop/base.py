"""Base abstractions for desktop modules.

Mirrors :mod:`recon_platform.vision.base`: a ``DesktopModule`` is the smallest
unit of desktop observation / interaction. It receives a :class:`DesktopContext`
(the live :class:`~recon_platform.desktop.session.DesktopSession`, the target,
settings, and a shared ``_cache`` for cross-module state — notably the
Vision-detected on-screen elements the agent injects) and returns a
:class:`~recon_platform.domain.schemas.ReconResult`.

Like the recon / browser / vision modules, desktop modules must be resilient: I/O
and backend errors are captured in ``result.errors`` rather than raised, so one
failing module never aborts a run.
"""

from __future__ import annotations

import abc
from typing import Any

from recon_platform.core.config import Settings
from recon_platform.domain.enums import ToolPermission
from recon_platform.domain.schemas import ReconResult


class DesktopContext:
    """Shared resources handed to every desktop module during a run.

    ``session`` is the live :class:`~recon_platform.desktop.session.DesktopSession`
    (typed ``Any`` so this module never imports the desktop backend stack). It
    discovers windows, captures the screen, reads/writes the clipboard, and sends
    gated input. ``_cache`` is the same side-channel used by the other contexts:
    the agent stashes the Vision agent's detected elements under ``"ui_elements"``
    so the interaction module can click them "by sight".
    """

    def __init__(
        self,
        target: str,
        session: Any,
        settings: Settings,
    ) -> None:
        self.target = target
        self.session = session
        self.settings = settings
        self._cache: dict[str, Any] = {}


class DesktopModule(abc.ABC):
    """Abstract base for a desktop observation / interaction capability."""

    #: Stable identifier used in results and reports.
    name: str = "desktop_module"
    #: Human description.
    description: str = ""
    #: Capabilities required. Read-only modules declare FILESYSTEM_WRITE (they may
    #: write screenshot evidence); interaction modules additionally declare DESKTOP.
    permissions: tuple[ToolPermission, ...] = (ToolPermission.FILESYSTEM_WRITE,)

    @abc.abstractmethod
    async def run(self, ctx: DesktopContext) -> ReconResult:
        """Execute the module and return a ReconResult (never raise for I/O)."""
        raise NotImplementedError

    def _empty(self) -> ReconResult:
        return ReconResult(task_id="", module=self.name)
