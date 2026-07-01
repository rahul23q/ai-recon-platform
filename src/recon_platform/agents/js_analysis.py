"""JavaScript-analysis agent — maps the client-side attack surface.

The Phase-8 agent gathers the ``JS_FILE`` assets earlier agents discovered (the
Browser agent's ``<script src>`` inventory, plus any from passive recon),
**passively fetches** each script body (GET-only, size-capped, failure-tolerant),
then runs the JS modules (endpoint extraction, secret detection, source-map
discovery) over the text, adds the discovered assets/relations to the graph,
records a reasoning trace per module, and announces ``js.*`` events on the A2A bus.

It is **opt-in and self-degrading**: it declares ``NETWORK_PASSIVE`` (the same
posture as the passive-recon modules) and, when disabled, offline, or with nothing
to fetch, records a skip / yields empty results — it never raises. Fetching is
isolated behind :func:`recon_platform.js_analysis.fetcher.fetch_js` so it is a
single, easily-mocked seam.
"""

from __future__ import annotations

import httpx

from recon_platform.agents.base import BaseAgent
from recon_platform.core.config import Settings
from recon_platform.domain.enums import AgentRole, AssetType
from recon_platform.domain.interfaces import KnowledgeGraph, LLMProvider, Memory, MessageBus
from recon_platform.domain.schemas import Asset, EngagementContext, ReasoningTrace, Relation
from recon_platform.js_analysis.analyzers import find_source_maps
from recon_platform.js_analysis.base import JSContext
from recon_platform.js_analysis.fetcher import fetch_js
from recon_platform.js_analysis.modules import build_js_modules

# Per-module → dashboard event name (announced on the bus for observability).
_MODULE_EVENTS = {
    "js_endpoints": "js.endpoints",
    "js_secrets": "js.secret_detected",
    "js_source_maps": "js.source_map",
}


class JSAnalysisAgent(BaseAgent):
    def __init__(
        self,
        bus: MessageBus,
        memory: Memory,
        llm: LLMProvider,
        graph: KnowledgeGraph,
        settings: Settings,
    ) -> None:
        super().__init__(AgentRole.JS_ANALYSIS, bus, memory, llm)
        self.graph = graph
        self.settings = settings

    async def run_js_analysis(
        self, engagement: EngagementContext
    ) -> tuple[list[Asset], list[Relation]]:
        # -- graceful skip ---------------------------------------------------
        js = self.settings.js_analysis
        if not js.enabled:
            return await self._skip("js analysis disabled (settings.js_analysis.enabled=False)")

        js_urls = self._gather_js_urls()
        if not js_urls and js.fetch:
            return await self._skip("no JavaScript files discovered to analyze")

        sources = await self._fetch_sources(js_urls) if js.fetch else {}
        await self.announce(
            recipient=AgentRole.ANALYSIS,
            reason="js.started",
            result={"scripts": len(js_urls), "fetched": len(sources)},
            confidence=0.9,
        )

        ctx = JSContext(engagement.target, self.settings, sources=sources)
        modules = build_js_modules(self.settings)
        all_assets: list[Asset] = []
        all_relations: list[Relation] = []

        for module in modules:
            self.log.info("js.module.start", module=module.name)
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
                    recovery_plan="re-run once more scripts are captured" if result.errors else "",
                )
            )
            await self.announce(
                recipient=AgentRole.ANALYSIS,
                reason=_MODULE_EVENTS.get(module.name, f"js.{module.name}"),
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
            reason="js.completed",
            result={"assets": len(all_assets), "relations": len(all_relations)},
            confidence=0.9,
        )
        self.log.info("js.complete", assets=len(all_assets), relations=len(all_relations))
        return all_assets, all_relations

    # -- helpers ------------------------------------------------------------
    def _gather_js_urls(self) -> list[str]:
        """Collect distinct http(s) JS_FILE URLs from the knowledge graph."""
        urls: list[str] = []
        seen: set[str] = set()
        for asset in self.graph.assets(AssetType.JS_FILE):
            url = asset.value
            if url.lower().startswith(("http://", "https://")) and url not in seen:
                seen.add(url)
                urls.append(url)
        return urls[: max(0, self.settings.js_analysis.max_files)]

    async def _fetch_sources(self, urls: list[str]) -> dict[str, str]:
        """GET each script (and, if enabled, its source map) into a {url: text} map."""
        js = self.settings.js_analysis
        sources: dict[str, str] = {}
        async with httpx.AsyncClient(
            timeout=self.settings.http.timeout_seconds,
            headers={"User-Agent": self.settings.http.user_agent},
            verify=self.settings.http.verify_tls,
            follow_redirects=True,
        ) as client:
            for url in urls:
                body = await fetch_js(client, url, max_bytes=js.max_bytes)
                if body is not None:
                    sources[url] = body
            if js.fetch_source_maps:
                # Second pass: fetch discovered source maps so secrets/endpoints in
                # the original source are analyzed too.
                map_urls: list[str] = []
                for url, body in list(sources.items()):
                    map_urls += find_source_maps(body, base_url=url)
                for map_url in map_urls[: js.max_files]:
                    if map_url in sources:
                        continue
                    body = await fetch_js(client, map_url, max_bytes=js.max_bytes)
                    if body is not None:
                        sources[map_url] = body
        return sources

    async def _skip(self, reason: str) -> tuple[list[Asset], list[Relation]]:
        """Record + announce a clean skip and return empty results."""
        self.log.info("js.skip", reason=reason)
        await self.record(
            ReasoningTrace(
                agent=self.role,
                action="skip",
                observation=reason,
                result="js analysis step skipped",
                reflection="graceful degradation — pipeline unaffected",
                confidence=1.0,
                next_action="continue to analysis",
            )
        )
        await self.announce(
            recipient=AgentRole.ANALYSIS,
            reason=f"js.skipped: {reason}",
            result={"skipped": True, "reason": reason},
            confidence=1.0,
        )
        return [], []
