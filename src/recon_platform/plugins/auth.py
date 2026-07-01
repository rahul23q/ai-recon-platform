"""Authentication plugin — surfaces the auth workflows in the MCP catalogue.

Authentication is intrusive and inherently agent-driven: each workflow needs a
live browser session and gated credentials, so — unlike the passive plugins —
these tools cannot meaningfully run standalone from the MCP registry. They are
registered so the catalogue documents the capability (name, description, and the
``BROWSER`` + ``NETWORK_ACTIVE`` permissions it requires); invoking one directly
returns a clean note directing the caller to run the Authentication agent.
"""

from __future__ import annotations

from typing import Any

from recon_platform.auth.workflows import AuthWorkflow
from recon_platform.domain.enums import ToolPermission
from recon_platform.plugins.base import BasePlugin, BaseTool


class AuthWorkflowTool(BaseTool):
    """Adapter surfacing an `AuthWorkflow` as a (descriptor-only) `Tool`."""

    def __init__(self, workflow: AuthWorkflow) -> None:
        self._workflow = workflow
        self.name = f"auth.{workflow.name}"
        self.description = f"Authentication workflow: {workflow.name} (runs via the Auth agent)."
        self.permissions = [ToolPermission.BROWSER, ToolPermission.NETWORK_ACTIVE]
        self.input_schema = {
            "type": "object",
            "properties": {"target": {"type": "string"}},
        }
        self.output_schema = {
            "type": "object",
            "properties": {"skipped": {"type": "boolean"}, "note": {"type": "string"}},
        }

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        return {
            "skipped": True,
            "note": (
                "Authentication workflows require a live browser session and gated "
                "credentials; run the Authentication agent (RECON_AUTH__ENABLED=1 + "
                "RECON_AUTH__AUTHORIZED=1) rather than invoking this tool directly."
            ),
        }


class AuthenticationPlugin(BasePlugin):
    """Bundles the authentication workflows as MCP tools (Phase 9)."""

    name = "authentication"
    version = "0.9.0"
    description = "Authentication workflows (login, registration, forgot-password, admin probe)."

    def __init__(self, workflows: list[AuthWorkflow]) -> None:
        self._workflows = workflows

    def tools(self) -> list[BaseTool]:
        return [AuthWorkflowTool(w) for w in self._workflows]
