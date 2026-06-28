"""Reporting agent — assembles the final ReportBundle.

Collects the engagement, plan, discovered assets/relations (from the knowledge
graph), findings, and the full reasoning trace into a single bundle that the
renderers turn into Markdown/HTML/JSON.
"""

from __future__ import annotations

from recon_platform.agents.base import BaseAgent
from recon_platform.domain.enums import AgentRole
from recon_platform.domain.interfaces import KnowledgeGraph, LLMProvider, Memory, MessageBus
from recon_platform.domain.schemas import (
    EngagementContext,
    Finding,
    Plan,
    ReasoningTrace,
    ReportBundle,
)


class ReportingAgent(BaseAgent):
    def __init__(
        self, bus: MessageBus, memory: Memory, llm: LLMProvider, graph: KnowledgeGraph
    ) -> None:
        super().__init__(AgentRole.REPORTING, bus, memory, llm)
        self.graph = graph

    async def build(
        self,
        engagement: EngagementContext,
        plan: Plan,
        findings: list[Finding],
        executive_summary: str = "",
    ) -> ReportBundle:
        bundle = ReportBundle(
            engagement=engagement,
            plan=plan,
            assets=self.graph.assets(),
            relations=self.graph.relations(),
            findings=findings,
            traces=self.memory.traces(),
        )
        if executive_summary:
            bundle.engagement.notes = executive_summary

        await self.record(
            ReasoningTrace(
                agent=self.role,
                action="assemble_report",
                observation=(
                    f"{len(bundle.assets)} assets, {len(bundle.findings)} findings"
                ),
                result="bundle ready",
                confidence=0.95,
            )
        )
        await self.announce(
            recipient=None,
            reason="report bundle assembled",
            result={
                "assets": len(bundle.assets),
                "findings": len(bundle.findings),
                "severity_counts": bundle.severity_counts,
            },
            confidence=0.95,
        )
        return bundle
