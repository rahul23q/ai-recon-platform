"""Composition root: build a fully-wired DI container.

This is the single place where concrete implementations are bound to their
Protocol contracts. Swap any binding here (e.g. a Redis bus, a vector memory)
without touching agents or orchestration.
"""

from __future__ import annotations

import httpx

from recon_platform.a2a.bus import InMemoryMessageBus
from recon_platform.core.config import Settings, get_settings
from recon_platform.core.container import Container
from recon_platform.core.logging import configure_logging
from recon_platform.domain.interfaces import (
    KnowledgeGraph,
    LLMProvider,
    Memory,
    MessageBus,
    ToolRegistry,
)
from recon_platform.knowledge_graph.graph import InMemoryKnowledgeGraph
from recon_platform.llm.provider import build_llm_provider
from recon_platform.mcp.registry import InMemoryToolRegistry
from recon_platform.memory.store import InMemoryMemory
from recon_platform.plugins.base import PassiveReconPlugin
from recon_platform.plugins.registry import PluginManager
from recon_platform.recon.base import ModuleContext
from recon_platform.recon.modules import build_passive_modules


def build_container(settings: Settings | None = None) -> Container:
    """Construct and wire the application container."""
    settings = settings or get_settings()
    configure_logging(settings.log_level, settings.log_json)

    container = Container()
    container.register_instance(Settings, settings)
    container.register_singleton(MessageBus, lambda _c: InMemoryMessageBus())
    container.register_singleton(Memory, lambda _c: InMemoryMemory())
    container.register_singleton(KnowledgeGraph, lambda _c: InMemoryKnowledgeGraph())
    container.register_singleton(LLMProvider, lambda c: build_llm_provider(c.resolve(Settings)))
    container.register_singleton(ToolRegistry, lambda _c: InMemoryToolRegistry())

    # Register the built-in passive-recon plugin's tools into the MCP registry.
    registry = container.resolve(ToolRegistry)  # type: ignore[type-abstract]
    manager = PluginManager(registry)

    def _ctx_factory() -> ModuleContext:
        client = httpx.AsyncClient(
            timeout=settings.http.timeout_seconds,
            headers={"User-Agent": settings.http.user_agent},
            verify=settings.http.verify_tls,
        )
        return ModuleContext(settings.authorized_targets[0] if settings.authorized_targets else "",
                             client, settings)

    manager.register(PassiveReconPlugin(build_passive_modules(), _ctx_factory))
    container.register_instance(PluginManager, manager)

    return container
