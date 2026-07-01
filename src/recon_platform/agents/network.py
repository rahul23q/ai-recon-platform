"""Network agent — correlates captured request/response data into findings.

The Phase-6 counterpart to the other perception agents, but instead of gathering
new data it **reasons over what earlier agents already observed**: it snapshots
the HTTP headers, cookies, tokens (secrets), and endpoints/URLs already in the
knowledge graph, runs the network modules (JWT inspection, API-traffic
classification, WebSocket review, CORS hygiene), adds the discovered network-layer
assets/relations back to the graph, records a reasoning trace per module, and
announces structured ``network.*`` events on the A2A bus.

It is **opt-in and self-degrading** and, unlike active recon, entirely passive —
it issues no network I/O and has no external dependency. When network analysis is
disabled it records a skip trace, announces it, and returns empty results; it
never raises.
"""

from __future__ import annotations

from recon_platform.agents.base import BaseAgent
from recon_platform.core.config import Settings
from recon_platform.domain.enums import AgentRole, AssetType
from recon_platform.domain.interfaces import KnowledgeGraph, LLMProvider, Memory, MessageBus
from recon_platform.domain.schemas import Asset, EngagementContext, ReasoningTrace, Relation
from recon_platform.network.base import NetworkContext
from recon_platform.network.modules import build_network_modules

# Per-module → dashboard event name (announced on the bus for observability).
_MODULE_EVENTS = {
    "jwt_inspection": "network.jwt",
    "api_classification": "network.api",
    "websocket_review": "network.websocket",
    "cors_hygiene": "network.cors",
}


class NetworkAgent(BaseAgent):
    def __init__(
        self,
        bus: MessageBus,
        memory: Memory,
        llm: LLMProvider,
        graph: KnowledgeGraph,
        settings: Settings,
    ) -> None:
        super().__init__(AgentRole.NETWORK, bus, memory, llm)
        self.graph = graph
        self.settings = settings

    async def run_network(
        self, engagement: EngagementContext
    ) -> tuple[list[Asset], list[Relation]]:
        # -- graceful skip ---------------------------------------------------
        if not self.settings.network.enabled:
            return await self._skip("network analysis disabled (settings.network.enabled=False)")

        ctx = self._snapshot(engagement.target)
        await self.announce(
            recipient=AgentRole.ANALYSIS,
            reason="network.started",
            result={
                "headers": len(ctx.headers),
                "tokens": len(ctx.tokens),
                "endpoints": len(ctx.endpoints),
            },
            confidence=0.9,
        )

        modules = build_network_modules(self.settings)
        all_assets: list[Asset] = []
        all_relations: list[Relation] = []

        for module in modules:
            self.log.info("network.module.start", module=module.name)
            result = await module.run(ctx)

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
                    recovery_plan=(
                        "re-run once more request/response data is captured"
                        if result.errors
                        else ""
                    ),
                )
            )
            await self.announce(
                recipient=AgentRole.ANALYSIS,
                reason=_MODULE_EVENTS.get(module.name, f"network.{module.name}"),
                result={
                    "module": module.name,
                    "assets": len(result.assets),
                    "relations": len(result.relations),
                    "notes": result.notes,
                    "errors": result.errors,
                },
                confidence=0.5 if result.errors else 0.85,
            )

        await self.announce(
            recipient=AgentRole.ANALYSIS,
            reason="network.completed",
            result={"assets": len(all_assets), "relations": len(all_relations)},
            confidence=0.9,
        )
        self.log.info(
            "network.complete", assets=len(all_assets), relations=len(all_relations)
        )
        return all_assets, all_relations

    # -- helpers ------------------------------------------------------------
    def _snapshot(self, target: str) -> NetworkContext:
        """Snapshot the network-relevant assets so modules stay graph-free.

        Tokens are sourced from ``SECRET`` assets (Authorization bearers, API
        keys OCR'd or captured); endpoints from both ``ENDPOINT`` and ``URL``
        assets so JWTs / API paths / WebSocket URLs are caught wherever they live.
        """
        endpoints = self.graph.assets(AssetType.ENDPOINT) + self.graph.assets(AssetType.URL)
        return NetworkContext(
            target,
            self.settings,
            headers=self.graph.assets(AssetType.HEADER),
            cookies=self.graph.assets(AssetType.COOKIE),
            tokens=self.graph.assets(AssetType.SECRET),
            endpoints=endpoints,
        )

    async def _skip(self, reason: str) -> tuple[list[Asset], list[Relation]]:
        """Record + announce a clean skip and return empty results."""
        self.log.info("network.skip", reason=reason)
        await self.record(
            ReasoningTrace(
                agent=self.role,
                action="skip",
                observation=reason,
                result="network step skipped",
                reflection="graceful degradation — pipeline unaffected",
                confidence=1.0,
                next_action="continue to analysis",
            )
        )
        await self.announce(
            recipient=AgentRole.ANALYSIS,
            reason=f"network.skipped: {reason}",
            result={"skipped": True, "reason": reason},
            confidence=1.0,
        )
        return [], []
