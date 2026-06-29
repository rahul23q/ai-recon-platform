"""Vision plugin — exposes the built-in vision modules as MCP tools.

Mirrors the Browser plugin (``plugins.base.BrowserPlugin``): each
:class:`~recon_platform.vision.base.VisionModule` is surfaced uniformly in the MCP
catalogue so it is discoverable and invocable like any other tool. The context
factory yields a live :class:`~recon_platform.vision.base.VisionContext`; the
heavy vision stack is imported lazily by the session, so registering these tools
never pulls in the optional ``vision`` extra.
"""

from __future__ import annotations

from typing import Any

from recon_platform.domain.enums import ToolPermission
from recon_platform.plugins.base import BasePlugin, BaseTool
from recon_platform.vision.base import VisionContext, VisionModule


class VisionModuleTool(BaseTool):
    """Adapter exposing a `VisionModule` as a `Tool`."""

    def __init__(self, module: VisionModule, context_factory) -> None:
        self._module = module
        self._context_factory = context_factory  # () -> VisionContext
        self.name = f"vision.{module.name}"
        self.description = module.description
        self.permissions = list(module.permissions) or [ToolPermission.FILESYSTEM_READ]
        self.input_schema = {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "screenshots": {"type": "array", "items": {"type": "string"}},
            },
        }
        self.output_schema = {
            "type": "object",
            "properties": {
                "assets": {"type": "array"},
                "relations": {"type": "array"},
                "notes": {"type": "array"},
                "errors": {"type": "array"},
            },
        }

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        ctx: VisionContext = self._context_factory()
        if "screenshots" in kwargs and kwargs["screenshots"]:
            ctx.screenshots = list(kwargs["screenshots"])
        result = await self._module.run(ctx)
        return result.model_dump(mode="json")


class VisionPlugin(BasePlugin):
    """Bundles the built-in vision modules as tools (Phase 3)."""

    name = "vision"
    version = "0.3.0"
    description = "OCR + visual-intelligence modules over browser screenshots."

    def __init__(self, modules: list[VisionModule], context_factory) -> None:
        self._modules = modules
        self._context_factory = context_factory

    def tools(self) -> list[BaseTool]:
        return [VisionModuleTool(m, self._context_factory) for m in self._modules]
