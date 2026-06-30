"""Active-recon agent — runs external tools and merges results into the graph.

The Phase-5 counterpart to :class:`~recon_platform.agents.recon.ReconAgent`, but
for **intrusive** tooling: it builds the configured tool set, runs each through
the shared async :class:`~recon_platform.active_recon.runner.ToolRunner`,
normalizes their output into assets/relations, merges them into the knowledge
graph, records a reasoning trace per tool, stores each full execution in episodic
memory, and emits structured ``active.*`` events on the A2A bus.

It is **opt-in and self-degrading** behind a *two-key authorization* posture: it
runs only when ``settings.active_recon.enabled`` **and**
``settings.active_recon.authorized`` are set **and** the target passes the
authorization gate. Any other state records a skip trace and returns empty —
nothing intrusive ever happens by accident. Individual tools whose binary is
absent are skipped cleanly, so a partially-installed toolbox still works.
"""

from __future__ import annotations

from recon_platform.active_recon.base import ActiveToolContext
from recon_platform.active_recon.runner import ToolRunner
from recon_platform.active_recon.tools import build_active_tools
from recon_platform.agents.base import BaseAgent
from recon_platform.core.config import Settings
from recon_platform.core.exceptions import UnauthorizedTargetError
from recon_platform.domain.enums import AgentRole, MemoryScope
from recon_platform.domain.interfaces import KnowledgeGraph, LLMProvider, Memory, MessageBus
from recon_platform.domain.schemas import Asset, EngagementContext, ReasoningTrace, Relation
from recon_platform.recon.authorization import ensure_authorized


class ActiveReconAgent(BaseAgent):
    def __init__(
        self,
        bus: MessageBus,
        memory: Memory,
        llm: LLMProvider,
        graph: KnowledgeGraph,
        settings: Settings,
    ) -> None:
        super().__init__(AgentRole.ACTIVE_RECON, bus, memory, llm)
        self.graph = graph
        self.settings = settings

    async def run_active(
        self, engagement: EngagementContext
    ) -> tuple[list[Asset], list[Relation]]:
        # -- authorization (two keys) + graceful skip ------------------------
        ar = self.settings.active_recon
        if not ar.enabled:
            return await self._skip("active recon disabled (settings.active_recon.enabled=False)")
        if not ar.authorized:
            return await self._skip(
                "active recon not authorized (set settings.active_recon.authorized=True to "
                "acknowledge you are permitted to actively scan this target)"
            )
        try:
            ensure_authorized(engagement.target, self.settings)
        except UnauthorizedTargetError as exc:
            return await self._skip(f"target failed authorization gate: {exc}")

        tools = self._select_tools()
        await self.announce(
            recipient=AgentRole.ANALYSIS,
            reason="active.started",
            result={"tools": [t.name for t in tools], "target": engagement.target},
            confidence=0.9,
        )

        runner = ToolRunner(
            default_timeout=ar.timeout_seconds,
            max_output_bytes=ar.max_output_bytes,
        )
        ctx = ActiveToolContext(engagement.target, runner, self.settings)
        all_assets: list[Asset] = []
        all_relations: list[Relation] = []

        for tool in tools:
            self.log.info("active.tool.start", tool=tool.name)
            result, execution = await tool.run(ctx)

            for asset in result.assets:
                self.graph.add_asset(asset)
                all_assets.append(asset)
            for rel in result.relations:
                self.graph.add_relation(rel)
                all_relations.append(rel)

            # Persist the full execution record (stdout/stderr/exit/time) so it is
            # retrievable later without bloating the graph or the report.
            await self.memory.remember(
                MemoryScope.EPISODIC,
                f"active_recon:{engagement.id}:{tool.name}",
                execution.model_dump(mode="json"),
            )

            await self.record(
                ReasoningTrace(
                    agent=self.role,
                    action=f"run:{tool.name}",
                    observation=execution.summary(),
                    result=f"{len(result.assets)} assets, {len(result.relations)} relations; "
                    + ("; ".join(result.notes) or "ok"),
                    reflection="; ".join(result.errors) or "no errors",
                    tool=tool.name,
                    confidence=0.5 if (result.errors or execution.timed_out) else 0.85,
                    recovery_plan=(
                        "increase timeout / retry / verify the tool is installed"
                        if (result.errors or execution.timed_out)
                        else ""
                    ),
                )
            )
            await self.announce(
                recipient=AgentRole.ANALYSIS,
                reason=f"active.tool.{tool.name}",
                result={
                    "tool": tool.name,
                    "skipped": execution.skipped,
                    "timed_out": execution.timed_out,
                    "exit_code": execution.exit_code,
                    "duration_seconds": round(execution.duration_seconds, 2),
                    "assets": len(result.assets),
                    "relations": len(result.relations),
                    "notes": result.notes,
                    "errors": result.errors,
                },
                confidence=0.5 if (result.errors or execution.timed_out) else 0.85,
            )

        await self.announce(
            recipient=AgentRole.ANALYSIS,
            reason="active.completed",
            result={"assets": len(all_assets), "relations": len(all_relations)},
            confidence=0.9,
        )
        self.log.info(
            "active.complete", assets=len(all_assets), relations=len(all_relations)
        )
        return all_assets, all_relations

    # -- helpers ------------------------------------------------------------
    def _select_tools(self):
        """Return the configured tool set (all by default, or the named subset)."""
        tools = build_active_tools()
        wanted = {t.lower() for t in self.settings.active_recon.tools}
        if wanted:
            tools = [t for t in tools if t.name.lower() in wanted]
        return tools

    async def _skip(self, reason: str) -> tuple[list[Asset], list[Relation]]:
        """Record + announce a clean skip and return empty results."""
        self.log.info("active.skip", reason=reason)
        await self.record(
            ReasoningTrace(
                agent=self.role,
                action="skip",
                observation=reason,
                result="active recon step skipped",
                reflection="graceful degradation / safety gate — pipeline unaffected",
                confidence=1.0,
                next_action="continue to analysis",
            )
        )
        await self.announce(
            recipient=AgentRole.ANALYSIS,
            reason=f"active.skipped: {reason}",
            result={"skipped": True, "reason": reason},
            confidence=1.0,
        )
        return [], []
