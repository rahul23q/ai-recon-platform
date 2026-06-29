"""Base classes for tools and plugins.

A `Tool` is the uniform callable contract (the MCP-style surface): name,
description, declared permissions, and input/output JSON schemas. A `Plugin`
packages one or more tools with versioned metadata.

External integrations (nmap, nuclei, subfinder, httpx, …) are added by
subclassing `BaseTool` (wrapping the binary or API) and `BasePlugin`. The
foundation ships a recon-module adapter so the existing passive modules are
exposed as tools without rewriting them.
"""

from __future__ import annotations

import abc
from typing import Any

from recon_platform.browser.base import BrowserContext, BrowserModule
from recon_platform.domain.enums import ToolPermission
from recon_platform.recon.base import ModuleContext, ReconModule


class BaseTool(abc.ABC):
    """Concrete base implementing the `Tool` Protocol's attributes."""

    name: str = "tool"
    description: str = ""
    permissions: list[ToolPermission] = []
    input_schema: dict[str, Any] = {"type": "object", "properties": {}}
    output_schema: dict[str, Any] = {"type": "object", "properties": {}}

    @abc.abstractmethod
    async def run(self, **kwargs: Any) -> dict[str, Any]:
        raise NotImplementedError


class BasePlugin(abc.ABC):
    """Concrete base for plugins."""

    name: str = "plugin"
    version: str = "0.0.0"
    description: str = ""

    @abc.abstractmethod
    def tools(self) -> list[BaseTool]:
        raise NotImplementedError


class ReconModuleTool(BaseTool):
    """Adapter exposing a `ReconModule` as a `Tool`.

    Lets the MCP registry surface every passive module uniformly, so the same
    capability is reachable by agents, the API, or future MCP clients.
    """

    def __init__(self, module: ReconModule, context_factory) -> None:
        self._module = module
        self._context_factory = context_factory  # () -> ModuleContext
        self.name = f"recon.{module.name}"
        self.description = module.description
        self.permissions = list(module.permissions)
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
            },
        }

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        ctx: ModuleContext = self._context_factory()
        result = await self._module.run(ctx)
        return result.model_dump(mode="json")


class PassiveReconPlugin(BasePlugin):
    """Bundles the built-in passive recon modules as tools."""

    name = "passive-recon"
    version = "0.1.0"
    description = "Built-in pure-Python passive reconnaissance modules."

    def __init__(self, modules: list[ReconModule], context_factory) -> None:
        self._modules = modules
        self._context_factory = context_factory

    def tools(self) -> list[BaseTool]:
        return [ReconModuleTool(m, self._context_factory) for m in self._modules]


class BrowserModuleTool(BaseTool):
    """Adapter exposing a `BrowserModule` as a `Tool` (mirrors `ReconModuleTool`).

    Surfaces each browser module uniformly in the MCP catalogue. The context
    factory yields a live :class:`~recon_platform.browser.base.BrowserContext`
    (so invoking a browser tool drives a real, navigated page).
    """

    def __init__(self, module: BrowserModule, context_factory) -> None:
        self._module = module
        self._context_factory = context_factory  # () -> BrowserContext
        self.name = f"browser.{module.name}"
        self.description = module.description
        self.permissions = list(module.permissions)
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
            },
        }

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        ctx: BrowserContext = self._context_factory()
        result = await self._module.run(ctx)
        return result.model_dump(mode="json")


class BrowserPlugin(BasePlugin):
    """Bundles the built-in browser modules as tools (Phase 2)."""

    name = "browser"
    version = "0.2.0"
    description = "Playwright-driven browser observation modules."

    def __init__(self, modules: list[BrowserModule], context_factory) -> None:
        self._modules = modules
        self._context_factory = context_factory

    def tools(self) -> list[BaseTool]:
        return [BrowserModuleTool(m, self._context_factory) for m in self._modules]
