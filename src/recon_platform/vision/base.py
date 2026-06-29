"""Base abstractions for vision modules.

Mirrors :mod:`recon_platform.browser.base`: a ``VisionModule`` is the smallest
unit of visual observation. It receives a :class:`VisionContext` (the live
:class:`~recon_platform.vision.session.VisionSession`, the target, settings, the
list of screenshot paths to analyze, and a shared ``_cache`` for cross-module
state) and returns a :class:`~recon_platform.domain.schemas.ReconResult`.

Like the recon / browser modules, vision modules must be resilient: I/O and
model errors are captured in ``result.errors`` rather than raised, so one failing
module never aborts a run.
"""

from __future__ import annotations

import abc
from typing import Any

from recon_platform.core.config import Settings
from recon_platform.domain.enums import ToolPermission
from recon_platform.domain.schemas import ReconResult


class VisionContext:
    """Shared resources handed to every vision module during a run.

    ``session`` is the live :class:`~recon_platform.vision.session.VisionSession`
    (typed ``Any`` so this module never imports the heavy vision stack). It runs
    OCR + detection over an image. ``screenshots`` is the ordered list of image
    paths to analyze (reused from the Browser agent). ``_cache`` is the same
    side-channel used by the recon / browser contexts: the ingest module stores
    each image's :class:`~recon_platform.vision.models.VisionAnalysis` so later
    modules reuse it instead of re-running OCR.
    """

    def __init__(
        self,
        target: str,
        session: Any,
        settings: Settings,
        screenshots: list[str] | None = None,
    ) -> None:
        self.target = target
        self.session = session
        self.settings = settings
        self.screenshots: list[str] = list(screenshots or [])
        self._cache: dict[str, Any] = {}


class VisionModule(abc.ABC):
    """Abstract base for a visual-observation capability."""

    #: Stable identifier used in results and reports.
    name: str = "vision_module"
    #: Human description.
    description: str = ""
    #: Capabilities required; vision modules read local screenshot files.
    permissions: tuple[ToolPermission, ...] = (ToolPermission.FILESYSTEM_READ,)

    @abc.abstractmethod
    async def run(self, ctx: VisionContext) -> ReconResult:
        """Execute the module and return a ReconResult (never raise for I/O)."""
        raise NotImplementedError

    def _empty(self) -> ReconResult:
        return ReconResult(task_id="", module=self.name)
