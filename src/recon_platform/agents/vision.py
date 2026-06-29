"""Vision agent — analyzes browser screenshots and populates the knowledge graph.

The Phase-3 counterpart to :class:`~recon_platform.agents.browser.BrowserAgent`:
it gathers the screenshots the Browser agent captured (from the knowledge graph),
opens a :class:`~recon_platform.vision.session.VisionSession`, runs the vision
modules (OCR, object detection, page classification, QR codes), adds the
discovered assets/relations to the graph, records a reasoning trace per module,
and announces structured ``vision.*`` events on the A2A bus.

It is **opt-in and self-degrading**: when vision is disabled or no vision backend
is installed, ``run_vision`` records a skip trace, announces it, and returns empty
results — it never raises and never imports the heavy vision stack.
"""

from __future__ import annotations

from recon_platform.agents.base import BaseAgent
from recon_platform.core.config import Settings
from recon_platform.domain.enums import AgentRole, AssetType
from recon_platform.domain.interfaces import KnowledgeGraph, LLMProvider, Memory, MessageBus
from recon_platform.domain.schemas import Asset, EngagementContext, ReasoningTrace, Relation
from recon_platform.vision.base import VisionContext
from recon_platform.vision.modules import build_vision_modules
from recon_platform.vision.session import VisionSession, vision_available

# Per-module → dashboard event name (announced on the bus for observability).
_MODULE_EVENTS = {
    "screenshot_ingest": "vision.ingest",
    "ocr_text": "vision.ocr",
    "object_detection": "vision.object_detected",
    "qr_codes": "vision.qr_detected",
}


class VisionAgent(BaseAgent):
    def __init__(
        self,
        bus: MessageBus,
        memory: Memory,
        llm: LLMProvider,
        graph: KnowledgeGraph,
        settings: Settings,
    ) -> None:
        super().__init__(AgentRole.VISION, bus, memory, llm)
        self.graph = graph
        self.settings = settings

    async def run_vision(
        self, engagement: EngagementContext
    ) -> tuple[list[Asset], list[Relation]]:
        # -- graceful skip ---------------------------------------------------
        if not self.settings.vision.enabled:
            return await self._skip("vision disabled (settings.vision.enabled=False)")
        if not vision_available():
            return await self._skip(
                "no vision backend installed (pip install '.[vision]')"
            )

        screenshots, url_map = self._gather_screenshots()
        await self.announce(
            recipient=AgentRole.ANALYSIS,
            reason="vision.started",
            result={"screenshots": len(screenshots)},
            confidence=0.9,
        )

        modules = build_vision_modules()
        all_assets: list[Asset] = []
        all_relations: list[Relation] = []

        async with VisionSession(self.settings) as session:
            ctx = VisionContext(engagement.target, session, self.settings, screenshots)
            ctx._cache["screenshot_urls"] = url_map
            for module in modules:
                self.log.info("vision.module.start", module=module.name)
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
                            "retry OCR / fall back to null provider" if result.errors else ""
                        ),
                    )
                )
                await self.announce(
                    recipient=AgentRole.ANALYSIS,
                    reason=_MODULE_EVENTS.get(module.name, f"vision.{module.name}"),
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
            reason="vision.completed",
            result={"assets": len(all_assets), "relations": len(all_relations)},
            confidence=0.9,
        )
        self.log.info(
            "vision.complete", assets=len(all_assets), relations=len(all_relations)
        )
        return all_assets, all_relations

    # -- helpers ------------------------------------------------------------
    def _gather_screenshots(self) -> tuple[list[str], dict[str, str]]:
        """Collect screenshot paths the Browser agent stored on URL assets.

        Returns the ordered, de-duplicated path list and a ``{path: url_key}`` map
        so the ingest module can link each screenshot back to the page it depicts.
        We reuse existing screenshots — the Vision agent never re-captures.
        """
        paths: list[str] = []
        url_map: dict[str, str] = {}
        for url_asset in self.graph.assets(AssetType.URL):
            shot = url_asset.attributes.get("screenshot")
            if shot and shot not in url_map:
                paths.append(shot)
                url_map[shot] = url_asset.key
        return paths, url_map

    async def _skip(self, reason: str) -> tuple[list[Asset], list[Relation]]:
        """Record + announce a clean skip and return empty results."""
        self.log.info("vision.skip", reason=reason)
        await self.record(
            ReasoningTrace(
                agent=self.role,
                action="skip",
                observation=reason,
                result="vision step skipped",
                reflection="graceful degradation — pipeline unaffected",
                confidence=1.0,
                next_action="continue to analysis",
            )
        )
        await self.announce(
            recipient=AgentRole.ANALYSIS,
            reason=f"vision.skipped: {reason}",
            result={"skipped": True, "reason": reason},
            confidence=1.0,
        )
        return [], []
