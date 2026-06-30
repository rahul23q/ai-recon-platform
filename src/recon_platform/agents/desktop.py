"""Desktop agent — observes and (gated) interacts with the local desktop.

The Phase-4 counterpart to :class:`~recon_platform.agents.vision.VisionAgent`: it
gathers the on-screen elements the Vision agent detected (from the knowledge
graph), opens a :class:`~recon_platform.desktop.session.DesktopSession`, runs the
desktop modules (window discovery, screen capture, clipboard, UI interaction),
adds the discovered assets/relations to the graph, records a reasoning trace per
module, and announces structured ``desktop.*`` events on the A2A bus.

It is **opt-in and self-degrading**: when desktop automation is disabled or no
desktop backend is installed, ``run_desktop`` records a skip trace, announces it,
and returns empty results — it never raises and never imports the backend stack.
Synthetic input is additionally gated by ``settings.desktop.allow_input`` inside
the session, so the default posture observes without ever moving the real mouse.
"""

from __future__ import annotations

from recon_platform.agents.base import BaseAgent
from recon_platform.core.config import Settings
from recon_platform.desktop.base import DesktopContext
from recon_platform.desktop.modules import UI_ELEMENTS_KEY, build_desktop_modules
from recon_platform.desktop.session import DesktopSession, desktop_available
from recon_platform.domain.enums import AgentRole, AssetType
from recon_platform.domain.interfaces import KnowledgeGraph, LLMProvider, Memory, MessageBus
from recon_platform.domain.schemas import Asset, EngagementContext, ReasoningTrace, Relation

# Per-module → dashboard event name (announced on the bus for observability).
_MODULE_EVENTS = {
    "window_discovery": "desktop.window",
    "screen_capture": "desktop.capture",
    "clipboard": "desktop.clipboard",
    "ui_interaction": "desktop.action",
}


class DesktopAgent(BaseAgent):
    def __init__(
        self,
        bus: MessageBus,
        memory: Memory,
        llm: LLMProvider,
        graph: KnowledgeGraph,
        settings: Settings,
    ) -> None:
        super().__init__(AgentRole.DESKTOP, bus, memory, llm)
        self.graph = graph
        self.settings = settings

    async def run_desktop(
        self, engagement: EngagementContext
    ) -> tuple[list[Asset], list[Relation]]:
        # -- graceful skip ---------------------------------------------------
        if not self.settings.desktop.enabled:
            return await self._skip("desktop disabled (settings.desktop.enabled=False)")
        if not desktop_available():
            return await self._skip(
                "no desktop backend installed (pip install '.[desktop]')"
            )

        ui_elements = self._gather_ui_elements()
        await self.announce(
            recipient=AgentRole.ANALYSIS,
            reason="desktop.started",
            result={
                "ui_elements": len(ui_elements),
                "input_allowed": self.settings.desktop.allow_input,
            },
            confidence=0.9,
        )

        modules = build_desktop_modules()
        all_assets: list[Asset] = []
        all_relations: list[Relation] = []

        async with DesktopSession(self.settings) as session:
            ctx = DesktopContext(engagement.target, session, self.settings)
            ctx._cache[UI_ELEMENTS_KEY] = ui_elements
            for module in modules:
                self.log.info("desktop.module.start", module=module.name)
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
                            "re-discover windows / fall back to null backend"
                            if result.errors
                            else ""
                        ),
                    )
                )
                await self.announce(
                    recipient=AgentRole.ANALYSIS,
                    reason=_MODULE_EVENTS.get(module.name, f"desktop.{module.name}"),
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
            reason="desktop.completed",
            result={"assets": len(all_assets), "relations": len(all_relations)},
            confidence=0.9,
        )
        self.log.info(
            "desktop.complete", assets=len(all_assets), relations=len(all_relations)
        )
        return all_assets, all_relations

    # -- helpers ------------------------------------------------------------
    def _gather_ui_elements(self) -> list[dict]:
        """Collect Vision-detected on-screen elements that carry a bounding box.

        Reuses the ``VISUAL_ELEMENT`` assets the Vision agent wrote (never
        re-detects), so the Desktop agent can act "by sight". Returns a list of
        plain dicts (``key`` / ``label`` / ``box`` / ``confidence`` / ``screenshot``)
        the interaction module consumes without touching the graph itself.
        """
        elements: list[dict] = []
        for el in self.graph.assets(AssetType.VISUAL_ELEMENT):
            box = el.attributes.get("box")
            if not box:
                continue
            elements.append(
                {
                    "key": el.key,
                    "label": el.attributes.get("element_type", "element"),
                    "box": box,
                    "confidence": el.attributes.get("confidence", el.confidence),
                    "screenshot": el.attributes.get("screenshot", ""),
                }
            )
        return elements

    async def _skip(self, reason: str) -> tuple[list[Asset], list[Relation]]:
        """Record + announce a clean skip and return empty results."""
        self.log.info("desktop.skip", reason=reason)
        await self.record(
            ReasoningTrace(
                agent=self.role,
                action="skip",
                observation=reason,
                result="desktop step skipped",
                reflection="graceful degradation — pipeline unaffected",
                confidence=1.0,
                next_action="continue to analysis",
            )
        )
        await self.announce(
            recipient=AgentRole.ANALYSIS,
            reason=f"desktop.skipped: {reason}",
            result={"skipped": True, "reason": reason},
            confidence=1.0,
        )
        return [], []
