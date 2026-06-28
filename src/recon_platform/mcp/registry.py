"""In-memory MCP tool registry.

Implements the `ToolRegistry` Protocol. Every platform capability — recon
modules, external tool wrappers, future custom tools — is registered here and
described uniformly (name, description, permissions, input/output schema). This
is the single catalogue an MCP client (or an agent) browses and invokes.
"""

from __future__ import annotations

from typing import Any

from recon_platform.core.exceptions import ToolExecutionError
from recon_platform.core.logging import get_logger
from recon_platform.domain.interfaces import Tool

log = get_logger(__name__)


class InMemoryToolRegistry:
    """A simple name-keyed tool catalogue."""

    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        if tool.name in self._tools:
            log.warning("tool.duplicate", name=tool.name)
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool:
        if name not in self._tools:
            raise ToolExecutionError(name, "tool not registered")
        return self._tools[name]

    def list(self) -> list[Tool]:
        return list(self._tools.values())

    def describe(self) -> list[dict[str, Any]]:
        """Return MCP-style tool descriptors for discovery."""
        return [
            {
                "name": t.name,
                "description": t.description,
                "permissions": [p.value for p in t.permissions],
                "input_schema": t.input_schema,
                "output_schema": t.output_schema,
            }
            for t in self._tools.values()
        ]
