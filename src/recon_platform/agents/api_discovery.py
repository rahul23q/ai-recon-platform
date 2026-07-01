"""API-discovery agent — characterizes the APIs behind captured traffic.

The Phase-7 counterpart to :class:`~recon_platform.agents.network.NetworkAgent`,
and like it entirely **passive**: instead of gathering new data it snapshots the
endpoints/URLs, headers, JS files, and the Network agent's classified
``API_ENDPOINT`` assets already in the knowledge graph, runs the API modules
(REST inference, GraphQL / SOAP / gRPC discovery, auth-scheme detection), adds the
discovered API-layer assets/relations back to the graph, records a reasoning trace
per module, and announces structured ``api.*`` events on the A2A bus.

It is **opt-in and self-degrading**: it issues no network I/O and has no external
dependency. When API discovery is disabled it records a skip trace, announces it,
and returns empty results; it never raises.
"""

from __future__ import annotations

from recon_platform.agents.base import BaseAgent
from recon_platform.api_discovery.base import APIDiscoveryContext
from recon_platform.api_discovery.modules import build_api_modules
from recon_platform.core.config import Settings
from recon_platform.domain.enums import AgentRole, AssetType
from recon_platform.domain.interfaces import KnowledgeGraph, LLMProvider, Memory, MessageBus
from recon_platform.domain.schemas import Asset, EngagementContext, ReasoningTrace, Relation

# Per-module → dashboard event name (announced on the bus for observability).
_MODULE_EVENTS = {
    "rest_inference": "api.rest",
    "graphql_discovery": "api.graphql",
    "soap_grpc_discovery": "api.soap_grpc",
    "auth_scheme_detection": "api.auth",
}


class APIDiscoveryAgent(BaseAgent):
    def __init__(
        self,
        bus: MessageBus,
        memory: Memory,
        llm: LLMProvider,
        graph: KnowledgeGraph,
        settings: Settings,
    ) -> None:
        super().__init__(AgentRole.API, bus, memory, llm)
        self.graph = graph
        self.settings = settings

    async def run_api_discovery(
        self, engagement: EngagementContext
    ) -> tuple[list[Asset], list[Relation]]:
        # -- graceful skip ---------------------------------------------------
        if not self.settings.api_discovery.enabled:
            return await self._skip(
                "api discovery disabled (settings.api_discovery.enabled=False)"
            )

        ctx = self._snapshot(engagement.target)
        await self.announce(
            recipient=AgentRole.ANALYSIS,
            reason="api.started",
            result={"endpoints": len(ctx.endpoints), "headers": len(ctx.headers)},
            confidence=0.9,
        )

        modules = build_api_modules(self.settings)
        all_assets: list[Asset] = []
        all_relations: list[Relation] = []

        for module in modules:
            self.log.info("api.module.start", module=module.name)
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
                        "re-run once more endpoints/traffic are captured"
                        if result.errors
                        else ""
                    ),
                )
            )
            await self.announce(
                recipient=AgentRole.ANALYSIS,
                reason=_MODULE_EVENTS.get(module.name, f"api.{module.name}"),
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
            reason="api.completed",
            result={"assets": len(all_assets), "relations": len(all_relations)},
            confidence=0.9,
        )
        self.log.info(
            "api.complete", assets=len(all_assets), relations=len(all_relations)
        )
        return all_assets, all_relations

    # -- helpers ------------------------------------------------------------
    def _snapshot(self, target: str) -> APIDiscoveryContext:
        """Snapshot the API-relevant assets so modules stay graph-free.

        Endpoints are drawn from both ``ENDPOINT`` and ``URL`` assets so API paths
        are caught wherever they live; the Network agent's ``API_ENDPOINT`` assets
        are passed through as strong GraphQL/REST signals.
        """
        endpoints = self.graph.assets(AssetType.ENDPOINT) + self.graph.assets(AssetType.URL)
        return APIDiscoveryContext(
            target,
            self.settings,
            endpoints=endpoints,
            headers=self.graph.assets(AssetType.HEADER),
            js_files=self.graph.assets(AssetType.JS_FILE),
            api_endpoints=self.graph.assets(AssetType.API_ENDPOINT),
        )

    async def _skip(self, reason: str) -> tuple[list[Asset], list[Relation]]:
        """Record + announce a clean skip and return empty results."""
        self.log.info("api.skip", reason=reason)
        await self.record(
            ReasoningTrace(
                agent=self.role,
                action="skip",
                observation=reason,
                result="api discovery step skipped",
                reflection="graceful degradation — pipeline unaffected",
                confidence=1.0,
                next_action="continue to analysis",
            )
        )
        await self.announce(
            recipient=AgentRole.ANALYSIS,
            reason=f"api.skipped: {reason}",
            result={"skipped": True, "reason": reason},
            confidence=1.0,
        )
        return [], []
