"""Plugin manager: registers plugins and feeds their tools into a ToolRegistry."""

from __future__ import annotations

from recon_platform.core.logging import get_logger
from recon_platform.domain.interfaces import Plugin, ToolRegistry

log = get_logger(__name__)


class PluginManager:
    """Loads plugins and registers their tools into the MCP tool registry."""

    def __init__(self, registry: ToolRegistry) -> None:
        self._registry = registry
        self._plugins: list[Plugin] = []

    def register(self, plugin: Plugin) -> None:
        self._plugins.append(plugin)
        for tool in plugin.tools():
            self._registry.register(tool)
        log.info(
            "plugin.registered",
            plugin=plugin.name,
            version=plugin.version,
            tools=len(plugin.tools()),
        )

    def plugins(self) -> list[Plugin]:
        return list(self._plugins)
