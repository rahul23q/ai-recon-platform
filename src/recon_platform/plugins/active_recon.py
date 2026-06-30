"""Active-recon plugin — exposes the external tools as MCP tools.

Mirrors the Vision / Desktop plugins: each :class:`~recon_platform.active_recon.base.ExternalTool`
is surfaced uniformly in the MCP catalogue so it is discoverable and invocable
like any other tool, satisfying the Tool Protocol. The context factory yields a
live :class:`~recon_platform.active_recon.base.ActiveToolContext` with the shared
runner; binaries are discovered on ``PATH`` and never imported, so registering
these tools pulls in no dependencies and a missing binary simply reports skipped.
"""

from __future__ import annotations

from typing import Any

from recon_platform.active_recon.base import ActiveToolContext, ExternalTool
from recon_platform.plugins.base import BasePlugin, BaseTool


class ExternalToolTool(BaseTool):
    """Adapter exposing an `ExternalTool` as a `Tool`."""

    def __init__(self, tool: ExternalTool, context_factory) -> None:
        self._tool = tool
        self._context_factory = context_factory  # () -> ActiveToolContext
        self.name = f"active.{tool.name}"
        self.description = tool.description
        self.permissions = list(tool.permissions)
        self.input_schema = {
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
        }
        self.output_schema = {
            "type": "object",
            "properties": {
                "assets": {"type": "array"},
                "relations": {"type": "array"},
                "notes": {"type": "array"},
                "errors": {"type": "array"},
                "execution": {"type": "object"},
            },
        }

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        ctx: ActiveToolContext = self._context_factory()
        if kwargs.get("target"):
            ctx.target = str(kwargs["target"])
        result, execution = await self._tool.run(ctx)
        out = result.model_dump(mode="json")
        out["execution"] = execution.model_dump(mode="json")
        return out


class ActiveReconPlugin(BasePlugin):
    """Bundles the external active-recon tools as MCP tools (Phase 5)."""

    name = "active-recon"
    version = "0.5.0"
    description = "External active-reconnaissance tool integrations (httpx, nuclei, nmap, …)."

    def __init__(self, tools: list[ExternalTool], context_factory) -> None:
        self._tools = tools
        self._context_factory = context_factory

    def tools(self) -> list[BaseTool]:
        return [ExternalToolTool(t, self._context_factory) for t in self._tools]
