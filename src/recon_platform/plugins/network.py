"""Network plugin — exposes the built-in network modules as MCP tools.

Mirrors the Vision / Desktop plugins: each
:class:`~recon_platform.network.base.NetworkModule` is surfaced uniformly in the
MCP catalogue so it is discoverable and invocable like any other tool. The
modules are pure, dependency-free correlators over already-captured data, so
registering them pulls in nothing extra. The context factory yields a live
:class:`~recon_platform.network.base.NetworkContext`; when invoked standalone
(outside a full run) the snapshot is empty unless the caller supplies assets, so
the tool returns an empty result rather than issuing any network I/O.
"""

from __future__ import annotations

from typing import Any

from recon_platform.domain.enums import ToolPermission
from recon_platform.network.base import NetworkContext, NetworkModule
from recon_platform.plugins.base import BasePlugin, BaseTool


class NetworkModuleTool(BaseTool):
    """Adapter exposing a `NetworkModule` as a `Tool`."""

    def __init__(self, module: NetworkModule, context_factory) -> None:
        self._module = module
        self._context_factory = context_factory  # () -> NetworkContext
        self.name = f"network.{module.name}"
        self.description = module.description
        self.permissions = list(module.permissions) or [ToolPermission.NETWORK_PASSIVE]
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
        ctx: NetworkContext = self._context_factory()
        if kwargs.get("target"):
            ctx.target = str(kwargs["target"])
        result = await self._module.run(ctx)
        return result.model_dump(mode="json")


class NetworkPlugin(BasePlugin):
    """Bundles the built-in network modules as tools (Phase 6)."""

    name = "network"
    version = "0.6.0"
    description = "Request/response analysis modules (JWT, CORS, API traffic, WebSocket)."

    def __init__(self, modules: list[NetworkModule], context_factory) -> None:
        self._modules = modules
        self._context_factory = context_factory

    def tools(self) -> list[BaseTool]:
        return [NetworkModuleTool(m, self._context_factory) for m in self._modules]
