"""Desktop plugin — exposes the built-in desktop modules as MCP tools.

Mirrors the Vision plugin (:mod:`recon_platform.plugins.vision`): each
:class:`~recon_platform.desktop.base.DesktopModule` is surfaced uniformly in the
MCP catalogue so it is discoverable and invocable like any other tool. The
context factory yields a live :class:`~recon_platform.desktop.base.DesktopContext`;
the desktop backend stack is imported lazily by the session, so registering these
tools never pulls in the optional ``desktop`` extra.
"""

from __future__ import annotations

from typing import Any

from recon_platform.desktop.base import DesktopContext, DesktopModule
from recon_platform.domain.enums import ToolPermission
from recon_platform.plugins.base import BasePlugin, BaseTool


class DesktopModuleTool(BaseTool):
    """Adapter exposing a `DesktopModule` as a `Tool`."""

    def __init__(self, module: DesktopModule, context_factory) -> None:
        self._module = module
        self._context_factory = context_factory  # () -> DesktopContext
        self.name = f"desktop.{module.name}"
        self.description = module.description
        self.permissions = list(module.permissions) or [ToolPermission.FILESYSTEM_WRITE]
        self.input_schema = {
            "type": "object",
            "properties": {"target": {"type": "string"}},
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
        ctx: DesktopContext = self._context_factory()
        result = await self._module.run(ctx)
        return result.model_dump(mode="json")


class DesktopPlugin(BasePlugin):
    """Bundles the built-in desktop modules as tools (Phase 4)."""

    name = "desktop"
    version = "0.4.0"
    description = "Desktop / OS-automation modules (windows, capture, clipboard, input)."

    def __init__(self, modules: list[DesktopModule], context_factory) -> None:
        self._modules = modules
        self._context_factory = context_factory

    def tools(self) -> list[BaseTool]:
        return [DesktopModuleTool(m, self._context_factory) for m in self._modules]
