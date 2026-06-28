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

from recon_platform.agents import AnalysisAgent, PlannerAgent, ReconAgent, ReportingAgent
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

    async def _step_analyze(self, state: RunState) -> None:
        await self._emit("step", name="analyze")
        state.findings = await self._analysis.analyze()
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

        async def analyze_node(s: dict) -> dict:
            await self._step_analyze(s["state"])
            return s

        async def report_node(s: dict) -> dict:
            await self._step_report(s["state"])
            return s

        builder: StateGraph = StateGraph(dict)
        builder.add_node("plan", plan_node)
        builder.add_node("recon", recon_node)
        builder.add_node("analyze", analyze_node)
        builder.add_node("report", report_node)
        builder.add_edge(START, "plan")
        builder.add_edge("plan", "recon")
        builder.add_edge("recon", "analyze")
        builder.add_edge("analyze", "report")
        builder.add_edge("report", END)

        graph = builder.compile()
        await graph.ainvoke({"state": state})
