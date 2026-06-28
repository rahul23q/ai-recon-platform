"""Recon agent — runs passive recon modules and populates the knowledge graph.

Modules share a single `ModuleContext` (and HTTP client) so cached responses
(e.g. the home page fetched by http_headers) are reused by later modules such as
tech_fingerprint. Per-module failures are isolated and recorded.
"""

from __future__ import annotations

import httpx

from recon_platform.agents.base import BaseAgent
from recon_platform.core.config import Settings
from recon_platform.domain.enums import AgentRole
from recon_platform.domain.interfaces import KnowledgeGraph, LLMProvider, Memory, MessageBus
from recon_platform.domain.schemas import (
    Asset,
    EngagementContext,
    ReasoningTrace,
    Relation,
    Task,
)
from recon_platform.recon.base import ModuleContext
from recon_platform.recon.modules import build_passive_modules


class ReconAgent(BaseAgent):
    def __init__(
        self,
        bus: MessageBus,
        memory: Memory,
        llm: LLMProvider,
        graph: KnowledgeGraph,
        settings: Settings,
    ) -> None:
        super().__init__(AgentRole.RECON, bus, memory, llm)
        self.graph = graph
        self.settings = settings

    async def run_recon(
        self, engagement: EngagementContext, task: Task
    ) -> tuple[list[Asset], list[Relation]]:
        modules = build_passive_modules()
        wanted = set(task.params.get("modules", [m.name for m in modules]))
        modules = [m for m in modules if m.name in wanted]

        all_assets: list[Asset] = []
        all_relations: list[Relation] = []

        timeout = httpx.Timeout(self.settings.http.timeout_seconds)
        limits = httpx.Limits(max_connections=self.settings.http.max_concurrency)
        headers = {"User-Agent": self.settings.http.user_agent}

        async with httpx.AsyncClient(
            timeout=timeout,
            limits=limits,
            headers=headers,
            verify=self.settings.http.verify_tls,
        ) as client:
            ctx = ModuleContext(engagement.target, client, self.settings)
            for module in modules:
                self.log.info("recon.module.start", module=module.name)
                result = await module.run(ctx)
                result.task_id = task.id

                for asset in result.assets:
                    self.graph.add_asset(asset)
                    all_assets.append(asset)
                for rel in result.relations:
                    self.graph.add_relation(rel)
                    all_relations.append(rel)

                await self.record(
                    ReasoningTrace(
                        agent=self.role,
                        action=f"run:{module.name}",
                        observation=f"{len(result.assets)} assets, "
                        f"{len(result.relations)} relations",
                        result="; ".join(result.notes) or "ok",
                        reflection="; ".join(result.errors) or "no errors",
                        confidence=0.5 if result.errors else 0.85,
                        recovery_plan="retry or switch source" if result.errors else "",
                    )
                )
                await self.announce(
                    recipient=AgentRole.ANALYSIS,
                    reason=f"module {module.name} complete",
                    result={
                        "module": module.name,
                        "assets": len(result.assets),
                        "relations": len(result.relations),
                        "notes": result.notes,
                        "errors": result.errors,
                    },
                    confidence=0.5 if result.errors else 0.85,
                )

        self.log.info(
            "recon.complete", assets=len(all_assets), relations=len(all_relations)
        )
        return all_assets, all_relations
