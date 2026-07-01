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
from recon_platform.plugins.base import BrowserPlugin, PassiveReconPlugin
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

    # Browser modules are registered only when the browser is enabled, so the
    # optional Playwright extra stays unimported on default offline runs.
    if settings.browser.enabled:
        from recon_platform.browser.base import BrowserContext
        from recon_platform.browser.modules import build_browser_modules
        from recon_platform.browser.session import BrowserSession

        target = settings.authorized_targets[0] if settings.authorized_targets else ""

        def _browser_ctx_factory() -> BrowserContext:
            # Construction is cheap and import-free; Playwright loads lazily only
            # when the session is actually launched.
            return BrowserContext(target, BrowserSession(settings), settings)

        manager.register(BrowserPlugin(build_browser_modules(), _browser_ctx_factory))

    # Vision modules likewise register only when vision is enabled, keeping the
    # heavy OCR/vision extra unimported on default runs.
    if settings.vision.enabled:
        from recon_platform.plugins.vision import VisionPlugin
        from recon_platform.vision.base import VisionContext
        from recon_platform.vision.modules import build_vision_modules
        from recon_platform.vision.session import VisionSession

        v_target = settings.authorized_targets[0] if settings.authorized_targets else ""

        def _vision_ctx_factory() -> VisionContext:
            # Cheap, import-free construction; OCR/vision backends load lazily on
            # first use inside the session.
            return VisionContext(v_target, VisionSession(settings), settings)

        manager.register(VisionPlugin(build_vision_modules(), _vision_ctx_factory))

    # Desktop modules register only when desktop automation is enabled, keeping
    # the optional desktop (pyautogui/…) extra unimported on default runs.
    if settings.desktop.enabled:
        from recon_platform.desktop.base import DesktopContext
        from recon_platform.desktop.modules import build_desktop_modules
        from recon_platform.desktop.session import DesktopSession
        from recon_platform.plugins.desktop import DesktopPlugin

        d_target = settings.authorized_targets[0] if settings.authorized_targets else ""

        def _desktop_ctx_factory() -> DesktopContext:
            # Cheap, import-free construction; the desktop backend loads lazily on
            # first use inside the session.
            return DesktopContext(d_target, DesktopSession(settings), settings)

        manager.register(DesktopPlugin(build_desktop_modules(), _desktop_ctx_factory))

    # Active-recon tools register only when active recon is enabled. The tools are
    # external binaries discovered on PATH (never imported), so registration pulls
    # in no dependencies; a missing binary just reports skipped at run time.
    if settings.active_recon.enabled:
        from recon_platform.active_recon.base import ActiveToolContext
        from recon_platform.active_recon.runner import ToolRunner
        from recon_platform.active_recon.tools import build_active_tools
        from recon_platform.plugins.active_recon import ActiveReconPlugin

        a_target = settings.authorized_targets[0] if settings.authorized_targets else ""
        a_runner = ToolRunner(
            default_timeout=settings.active_recon.timeout_seconds,
            max_output_bytes=settings.active_recon.max_output_bytes,
        )

        def _active_ctx_factory() -> ActiveToolContext:
            return ActiveToolContext(a_target, a_runner, settings)

        manager.register(ActiveReconPlugin(build_active_tools(), _active_ctx_factory))

    # Network modules register only when network analysis is enabled. They are
    # pure, dependency-free correlators over data already in the graph, so
    # registration pulls in nothing extra and issues no I/O.
    if settings.network.enabled:
        from recon_platform.network.base import NetworkContext
        from recon_platform.network.modules import build_network_modules
        from recon_platform.plugins.network import NetworkPlugin

        n_target = settings.authorized_targets[0] if settings.authorized_targets else ""

        def _network_ctx_factory() -> NetworkContext:
            # Standalone (MCP) invocation gets an empty snapshot; during a full run
            # the NetworkAgent supplies the graph assets itself.
            return NetworkContext(n_target, settings)

        manager.register(NetworkPlugin(build_network_modules(settings), _network_ctx_factory))

    # API-discovery modules register only when the agent is enabled. Like the
    # network modules they are pure, dependency-free correlators over data already
    # in the graph, so registration pulls in nothing extra and issues no I/O.
    if settings.api_discovery.enabled:
        from recon_platform.api_discovery.base import APIDiscoveryContext
        from recon_platform.api_discovery.modules import build_api_modules
        from recon_platform.plugins.api_discovery import APIDiscoveryPlugin

        api_target = settings.authorized_targets[0] if settings.authorized_targets else ""

        def _api_ctx_factory() -> APIDiscoveryContext:
            # Standalone (MCP) invocation gets an empty snapshot; during a full run
            # the APIDiscoveryAgent supplies the graph assets itself.
            return APIDiscoveryContext(api_target, settings)

        manager.register(APIDiscoveryPlugin(build_api_modules(settings), _api_ctx_factory))

    container.register_instance(PluginManager, manager)

    return container
