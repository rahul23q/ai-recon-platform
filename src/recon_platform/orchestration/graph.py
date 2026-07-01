"""ReconOrchestrator — drives an engagement through the workflow.

Primary path is a deterministic async pipeline (Plan → Recon → Analyze →
Report) that always runs. When LangGraph is installed, the same step coroutines
are wired into a `StateGraph` so the flow is expressed as a real state machine;
the sequential path remains the guaranteed fallback.

The orchestrator also emits a live event stream (an asyncio queue) so the API
dashboard can render agent activity in real time, and forwards A2A timeline
messages onto that stream.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any

from recon_platform.agents import (
    ActiveReconAgent,
    AnalysisAgent,
    APIDiscoveryAgent,
    AuthenticationAgent,
    BrowserAgent,
    DesktopAgent,
    JSAnalysisAgent,
    NetworkAgent,
    PlannerAgent,
    ReconAgent,
    ReportingAgent,
    VerificationAgent,
    VisionAgent,
)
from recon_platform.core.config import Settings
from recon_platform.core.container import Container
from recon_platform.core.logging import get_logger
from recon_platform.domain.enums import TaskStatus
from recon_platform.domain.interfaces import KnowledgeGraph, LLMProvider, Memory, MessageBus
from recon_platform.domain.schemas import A2AMessage, EngagementContext, ReportBundle
from recon_platform.orchestration.state import RunState
from recon_platform.recon.authorization import ensure_authorized

log = get_logger(__name__)

_SENTINEL = object()


class ReconOrchestrator:
    """Coordinates the agents to execute a recon workflow."""

    def __init__(self, container: Container) -> None:
        self._settings = container.resolve(Settings)
        self._bus = container.resolve(MessageBus)  # type: ignore[type-abstract]
        self._memory = container.resolve(Memory)  # type: ignore[type-abstract]
        self._llm = container.resolve(LLMProvider)  # type: ignore[type-abstract]
        self._graph = container.resolve(KnowledgeGraph)  # type: ignore[type-abstract]

        self._planner = PlannerAgent(self._bus, self._memory, self._llm)
        self._recon = ReconAgent(
            self._bus, self._memory, self._llm, self._graph, self._settings
        )
        self._browser = BrowserAgent(
            self._bus, self._memory, self._llm, self._graph, self._settings
        )
        self._vision = VisionAgent(
            self._bus, self._memory, self._llm, self._graph, self._settings
        )
        self._verification = VerificationAgent(
            self._bus, self._memory, self._llm, self._graph, self._settings
        )
        self._desktop = DesktopAgent(
            self._bus, self._memory, self._llm, self._graph, self._settings
        )
        self._active = ActiveReconAgent(
            self._bus, self._memory, self._llm, self._graph, self._settings
        )
        self._auth = AuthenticationAgent(
            self._bus, self._memory, self._llm, self._graph, self._settings
        )
        self._js = JSAnalysisAgent(
            self._bus, self._memory, self._llm, self._graph, self._settings
        )
        self._network = NetworkAgent(
            self._bus, self._memory, self._llm, self._graph, self._settings
        )
        self._api = APIDiscoveryAgent(
            self._bus, self._memory, self._llm, self._graph, self._settings
        )
        self._analysis = AnalysisAgent(self._bus, self._memory, self._llm, self._graph)
        self._reporting = ReportingAgent(self._bus, self._memory, self._llm, self._graph)

        self._events: asyncio.Queue[Any] = asyncio.Queue()

    # -- event stream -------------------------------------------------------
    async def _emit(self, kind: str, **data: Any) -> None:
        await self._events.put({"event": kind, **data})

    async def _on_bus(self, message: A2AMessage) -> None:
        await self._events.put(
            {
                "event": "a2a",
                "sender": str(message.sender),
                "recipient": str(message.recipient) if message.recipient else None,
                "reason": message.reason,
                "result": message.result,
                "confidence": message.confidence,
            }
        )

    async def stream_events(self) -> AsyncIterator[dict[str, Any]]:
        """Yield run events until the run signals completion."""
        while True:
            item = await self._events.get()
            if item is _SENTINEL:
                break
            yield item

    # -- steps --------------------------------------------------------------
    async def _step_plan(self, state: RunState) -> None:
        await self._emit("step", name="plan")
        state.plan = await self._planner.make_plan(state.engagement)

    async def _step_recon(self, state: RunState) -> None:
        await self._emit("step", name="recon")
        assert state.plan is not None
        task = next(t for t in state.plan.tasks if t.assigned_role.value == "recon")
        task.status = TaskStatus.IN_PROGRESS
        assets, relations = await self._recon.run_recon(state.engagement, task)
        task.status = TaskStatus.COMPLETED
        state.assets, state.relations = assets, relations

    async def _step_browser(self, state: RunState) -> None:
        """Optional browser-agent step.

        Runs independently of the Planner's task graph (no new plan task), so the
        passive plan stays a fixed 3 tasks. The agent itself no-ops cleanly when
        the browser is disabled or Playwright is absent, so this step is always
        safe to call. Discovered assets/relations flow through the shared
        knowledge graph exactly like recon output.
        """
        if not self._settings.browser.enabled:
            return
        await self._emit("step", name="browser")
        assets, relations = await self._browser.run_browser(state.engagement)
        state.assets += assets
        state.relations += relations

    async def _step_vision(self, state: RunState) -> None:
        """Optional vision-agent step.

        Like the browser step, it runs independently of the Planner's task graph
        and no-ops cleanly when vision is disabled or no vision backend is
        installed. It analyzes the screenshots the browser step captured, so it
        runs after browser and before analysis; assets flow through the shared
        knowledge graph.
        """
        if not self._settings.vision.enabled:
            return
        await self._emit("step", name="vision")
        assets, relations = await self._vision.run_vision(state.engagement)
        state.assets += assets
        state.relations += relations

    async def _step_verify(self, state: RunState) -> None:
        """Cross-source verification stage (always runs, before analysis).

        Corroborates passive observations against the Browser agent's in-browser
        view so findings can be stamped Verified / Likely / Needs-Verification /
        False-Positive. Lightweight and dependency-free, so it runs every time —
        with no browser data it produces single-source 'likely' verdicts.
        """
        await self._emit("step", name="verification")
        state.verifications = await self._verification.verify(state.engagement)

    async def _step_desktop(self, state: RunState) -> None:
        """Optional desktop-agent step (after verification, before analysis).

        Like the browser / vision steps it runs independently of the Planner's
        task graph and no-ops cleanly when desktop automation is disabled or no
        desktop backend is installed. It runs after Vision/Verification so it can
        act "by sight" on the Vision agent's detected on-screen elements; the
        assets flow through the shared knowledge graph.
        """
        if not self._settings.desktop.enabled:
            return
        await self._emit("step", name="desktop")
        assets, relations = await self._desktop.run_desktop(state.engagement)
        state.assets += assets
        state.relations += relations

    async def _step_active(self, state: RunState) -> None:
        """Optional active-recon step (after desktop, before analysis).

        Runs the external tool plugins (httpx, subfinder, nuclei, nmap, …) behind
        a two-key authorization gate; it no-ops cleanly when active recon is
        disabled, unauthorized, or no tool binaries are installed. Discovered
        assets flow through the shared knowledge graph like every other agent's.
        """
        if not self._settings.active_recon.enabled:
            return
        await self._emit("step", name="active_recon")
        assets, relations = await self._active.run_active(state.engagement)
        state.assets += assets
        state.relations += relations

    async def _step_auth(self, state: RunState) -> None:
        """Optional authentication step (after active recon, before JS analysis).

        Active/intrusive: it submits credentials, so it runs behind a two-key
        authorization gate and no-ops cleanly when auth is disabled, unauthorized,
        or no browser backend is present. It runs after the collectors so login /
        admin URLs are already discovered; captured sessions flow to episodic
        memory (cookie values) and a masked SESSION asset (names only).
        """
        if not self._settings.auth.enabled:
            return
        await self._emit("step", name="authentication")
        assets, relations = await self._auth.run_auth(state.engagement)
        state.assets += assets
        state.relations += relations

    async def _step_js(self, state: RunState) -> None:
        """Optional JavaScript-analysis step (after active recon, before network).

        Passively fetches and analyzes the app's scripts, mapping the client-side
        attack surface (endpoints, parameters, secrets, source maps). It runs
        before the network and API-discovery agents so its JS-sourced endpoints
        feed their classification. No-ops cleanly when disabled or when no scripts
        were discovered.
        """
        if not self._settings.js_analysis.enabled:
            return
        await self._emit("step", name="js_analysis")
        assets, relations = await self._js.run_js_analysis(state.engagement)
        state.assets += assets
        state.relations += relations

    async def _step_network(self, state: RunState) -> None:
        """Optional network-analysis step (after active recon, before analysis).

        A passive correlation layer over the request/response data already in the
        graph (headers, cookies, tokens, endpoints): JWT inspection, CORS hygiene,
        API-traffic classification, and WebSocket review. Runs last among the
        collectors so every earlier agent's observations are available; it no-ops
        cleanly when network analysis is disabled and never issues new I/O.
        """
        if not self._settings.network.enabled:
            return
        await self._emit("step", name="network")
        assets, relations = await self._network.run_network(state.engagement)
        state.assets += assets
        state.relations += relations

    async def _step_api(self, state: RunState) -> None:
        """Optional API-discovery step (after network, before analysis).

        A passive characterization layer over the endpoints/headers/traffic already
        in the graph: REST inference, GraphQL / SOAP / gRPC discovery, and
        auth-scheme detection. Runs after the network agent so its classified API
        traffic is available; it no-ops cleanly when API discovery is disabled and
        never issues new I/O.
        """
        if not self._settings.api_discovery.enabled:
            return
        await self._emit("step", name="api_discovery")
        assets, relations = await self._api.run_api_discovery(state.engagement)
        state.assets += assets
        state.relations += relations

    async def _step_analyze(self, state: RunState) -> None:
        await self._emit("step", name="analyze")
        # Extend (not replace): browser-derived findings coexist with recon ones.
        state.findings += await self._analysis.analyze(state.verifications)
        state.executive_summary = await self._analysis.executive_summary(
            state.findings, state.engagement.target
        )

    async def _step_report(self, state: RunState) -> None:
        await self._emit("step", name="report")
        assert state.plan is not None
        state.bundle = await self._reporting.build(
            state.engagement, state.plan, state.findings, state.executive_summary
        )

    # -- run ----------------------------------------------------------------
    async def run(self, engagement: EngagementContext) -> ReportBundle:
        host = ensure_authorized(engagement.target, self._settings)
        engagement.target = host
        engagement.authorized = True

        await self._bus.subscribe("timeline", self._on_bus)
        await self._emit("run.start", target=host, llm=self._llm.available)

        state = RunState(engagement=engagement)
        try:
            if self._langgraph_available():
                await self._run_langgraph(state)
            else:
                await self._run_sequential(state)
        finally:
            await self._emit(
                "run.complete",
                findings=len(state.findings),
                assets=len(state.assets),
            )
            await self._events.put(_SENTINEL)

        assert state.bundle is not None
        return state.bundle

    async def _run_sequential(self, state: RunState) -> None:
        await self._step_plan(state)
        await self._step_recon(state)
        await self._step_browser(state)
        await self._step_vision(state)
        await self._step_verify(state)
        await self._step_desktop(state)
        await self._step_active(state)
        await self._step_auth(state)
        await self._step_js(state)
        await self._step_network(state)
        await self._step_api(state)
        await self._step_analyze(state)
        await self._step_report(state)

    # -- LangGraph integration ---------------------------------------------
    def _langgraph_available(self) -> bool:
        try:
            import langgraph  # noqa: F401
        except ImportError:
            return False
        return True

    async def _run_langgraph(self, state: RunState) -> None:
        """Express the pipeline as a LangGraph StateGraph.

        Nodes mutate the shared RunState in place and pass it along, so the
        graph is a faithful state machine over the same step coroutines.
        """
        from langgraph.graph import END, START, StateGraph

        async def plan_node(s: dict) -> dict:
            await self._step_plan(s["state"])
            return s

        async def recon_node(s: dict) -> dict:
            await self._step_recon(s["state"])
            return s

        async def browser_node(s: dict) -> dict:
            await self._step_browser(s["state"])
            return s

        async def vision_node(s: dict) -> dict:
            await self._step_vision(s["state"])
            return s

        async def verify_node(s: dict) -> dict:
            await self._step_verify(s["state"])
            return s

        async def desktop_node(s: dict) -> dict:
            await self._step_desktop(s["state"])
            return s

        async def active_node(s: dict) -> dict:
            await self._step_active(s["state"])
            return s

        async def auth_node(s: dict) -> dict:
            await self._step_auth(s["state"])
            return s

        async def js_node(s: dict) -> dict:
            await self._step_js(s["state"])
            return s

        async def network_node(s: dict) -> dict:
            await self._step_network(s["state"])
            return s

        async def api_node(s: dict) -> dict:
            await self._step_api(s["state"])
            return s

        async def analyze_node(s: dict) -> dict:
            await self._step_analyze(s["state"])
            return s

        async def report_node(s: dict) -> dict:
            await self._step_report(s["state"])
            return s

        builder: StateGraph = StateGraph(dict)
        builder.add_node("plan", plan_node)
        builder.add_node("recon", recon_node)
        builder.add_node("browser", browser_node)
        builder.add_node("vision", vision_node)
        builder.add_node("verification", verify_node)
        builder.add_node("desktop", desktop_node)
        builder.add_node("active_recon", active_node)
        builder.add_node("authentication", auth_node)
        builder.add_node("js_analysis", js_node)
        builder.add_node("network", network_node)
        builder.add_node("api_discovery", api_node)
        builder.add_node("analyze", analyze_node)
        builder.add_node("report", report_node)
        builder.add_edge(START, "plan")
        builder.add_edge("plan", "recon")
        builder.add_edge("recon", "browser")
        builder.add_edge("browser", "vision")
        builder.add_edge("vision", "verification")
        builder.add_edge("verification", "desktop")
        builder.add_edge("desktop", "active_recon")
        builder.add_edge("active_recon", "authentication")
        builder.add_edge("authentication", "js_analysis")
        builder.add_edge("js_analysis", "network")
        builder.add_edge("network", "api_discovery")
        builder.add_edge("api_discovery", "analyze")
        builder.add_edge("analyze", "report")
        builder.add_edge("report", END)

        graph = builder.compile()
        await graph.ainvoke({"state": state})
