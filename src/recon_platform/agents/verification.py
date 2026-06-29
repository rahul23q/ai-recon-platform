"""Verification agent — corroborates observations across sources before analysis.

Runs between the Browser/Vision agents and the Analysis agent. It reads the
``HEADER`` assets the passive recon and Browser agents wrote to the knowledge
graph and cross-checks the required security headers: a header is only confirmed
"missing" when an independent source agrees, eliminating the false-positive class
where a server sends e.g. Content-Security-Policy only to real browsers.

The agent never raises and never blocks the pipeline: with no browser data it
emits single-source ``LIKELY`` verdicts; the Analysis agent consumes the verdicts
to stamp each finding with a verification status, confidence, and sources.
"""

from __future__ import annotations

from recon_platform.agents.base import BaseAgent
from recon_platform.core.config import Settings
from recon_platform.domain.enums import AgentRole, VerificationStatus
from recon_platform.domain.interfaces import KnowledgeGraph, LLMProvider, Memory, MessageBus
from recon_platform.domain.schemas import EngagementContext, ReasoningTrace, Verification
from recon_platform.verification.headers import (
    collect_header_maps,
    compute_header_verifications,
)


class VerificationAgent(BaseAgent):
    def __init__(
        self,
        bus: MessageBus,
        memory: Memory,
        llm: LLMProvider,
        graph: KnowledgeGraph,
        settings: Settings,
    ) -> None:
        super().__init__(AgentRole.VERIFICATION, bus, memory, llm)
        self.graph = graph
        self.settings = settings

    async def verify(self, engagement: EngagementContext) -> list[Verification]:
        passive, browser, browser_observed = collect_header_maps(self.graph)
        verifications = compute_header_verifications(passive, browser, browser_observed)

        counts: dict[str, int] = {s.value: 0 for s in VerificationStatus}
        for v in verifications:
            counts[v.status.value] += 1

        await self.record(
            ReasoningTrace(
                agent=self.role,
                action="cross_verify_headers",
                observation=(
                    f"passive headers={len(passive)}, browser headers={len(browser)}, "
                    f"browser_observed={browser_observed}"
                ),
                result=", ".join(f"{k}: {v}" for k, v in counts.items() if v),
                reflection=(
                    "cross-source corroboration applied"
                    if browser_observed
                    else "single-source (browser not run) — verdicts are 'likely'"
                ),
                confidence=0.9 if browser_observed else 0.7,
                next_action="analysis",
            )
        )
        await self.announce(
            recipient=AgentRole.ANALYSIS,
            reason="verification.completed",
            result={
                "browser_observed": browser_observed,
                "verifications": len(verifications),
                "status_counts": counts,
            },
            confidence=0.9 if browser_observed else 0.7,
        )
        return verifications
