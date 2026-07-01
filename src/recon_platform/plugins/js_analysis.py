"""JavaScript-analysis plugin — exposes the built-in JS modules as MCP tools.

Mirrors the Network / API-discovery plugins: each
:class:`~recon_platform.js_analysis.base.JSModule` is surfaced uniformly in the
MCP catalogue so it is discoverable and invocable like any other tool. The modules
are pure over already-fetched script text, so registering them pulls in nothing
extra. The context factory yields a live
:class:`~recon_platform.js_analysis.base.JSContext`; when invoked standalone the
``sources`` map is empty unless the caller supplies script bodies, so the tool
returns an empty result rather than issuing any network I/O.
"""

from __future__ import annotations

from typing import Any

from recon_platform.domain.enums import ToolPermission
from recon_platform.js_analysis.base import JSContext, JSModule
from recon_platform.plugins.base import BasePlugin, BaseTool


class JSModuleTool(BaseTool):
    """Adapter exposing a `JSModule` as a `Tool`."""

    def __init__(self, module: JSModule, context_factory) -> None:
        self._module = module
        self._context_factory = context_factory  # () -> JSContext
        self.name = f"js.{module.name}"
        self.description = module.description
        self.permissions = list(module.permissions) or [ToolPermission.NETWORK_PASSIVE]
        self.input_schema = {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "sources": {"type": "object"},
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
        ctx: JSContext = self._context_factory()
        if kwargs.get("target"):
            ctx.target = str(kwargs["target"])
        if isinstance(kwargs.get("sources"), dict):
            ctx.sources = {str(k): str(v) for k, v in kwargs["sources"].items()}
        result = await self._module.run(ctx)
        return result.model_dump(mode="json")


class JSAnalysisPlugin(BasePlugin):
    """Bundles the built-in JavaScript-analysis modules as tools (Phase 8)."""

    name = "js-analysis"
    version = "0.8.0"
    description = "JavaScript-analysis modules (endpoints, secrets, source maps)."

    def __init__(self, modules: list[JSModule], context_factory) -> None:
        self._modules = modules
        self._context_factory = context_factory

    def tools(self) -> list[BaseTool]:
        return [JSModuleTool(m, self._context_factory) for m in self._modules]
