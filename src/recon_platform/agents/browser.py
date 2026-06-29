"""Browser agent — drives a real browser and populates the knowledge graph.

The Phase-2 counterpart to :class:`~recon_platform.agents.recon.ReconAgent`: it
opens a :class:`~recon_platform.browser.session.BrowserSession`, runs the browser
modules against the navigated page, adds the discovered assets/relations to the
knowledge graph, records a :class:`~recon_platform.domain.schemas.ReasoningTrace`
per module, and announces work on the A2A bus — the same loop ``ReconAgent`` uses.

It is **opt-in and self-degrading**: when the browser is disabled or Playwright
is not installed, ``run_browser`` records a skip trace, announces it, and returns
empty results — it never raises and never imports Playwright.
"""

from __future__ import annotations

from recon_platform.agents.base import BaseAgent
from recon_platform.browser.base import BrowserContext
from recon_platform.browser.modules import build_browser_modules
from recon_platform.browser.session import BrowserSession, playwright_available
from recon_platform.core.config import Settings
from recon_platform.domain.enums import AgentRole
from recon_platform.domain.interfaces import KnowledgeGraph, LLMProvider, Memory, MessageBus
from recon_platform.domain.schemas import Asset, EngagementContext, ReasoningTrace, Relation


class BrowserAgent(BaseAgent):
    def __init__(
        self,
        bus: MessageBus,
        memory: Memory,
        llm: LLMProvider,
        graph: KnowledgeGraph,
        settings: Settings,
    ) -> None:
        super().__init__(AgentRole.BROWSER, bus, memory, llm)
        self.graph = graph
        self.settings = settings

    async def run_browser(
        self, engagement: EngagementContext
    ) -> tuple[list[Asset], list[Relation]]:
        # -- graceful skip ---------------------------------------------------
        if not self.settings.browser.enabled:
            return await self._skip("browser disabled (settings.browser.enabled=False)")
        if not playwright_available():
            return await self._skip(
                "Playwright not installed (pip install '.[browser]' && playwright install chromium)"
            )

        modules = build_browser_modules()
        all_assets: list[Asset] = []
        all_relations: list[Relation] = []

        async with BrowserSession(self.settings) as session:
            ctx = BrowserContext(engagement.target, session, self.settings)
            for module in modules:
                self.log.info("browser.module.start", module=module.name)
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
                            "restart browser / recover session" if result.errors else ""
                        ),
                    )
                )
                await self.announce(
                    recipient=AgentRole.ANALYSIS,
                    reason=f"browser module {module.name} complete",
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
            "browser.complete", assets=len(all_assets), relations=len(all_relations)
        )
        return all_assets, all_relations

    async def _skip(self, reason: str) -> tuple[list[Asset], list[Relation]]:
        """Record + announce a clean skip and return empty results."""
        self.log.info("browser.skip", reason=reason)
        await self.record(
            ReasoningTrace(
                agent=self.role,
                action="skip",
                observation=reason,
                result="browser step skipped",
                reflection="graceful degradation — passive pipeline unaffected",
                confidence=1.0,
                next_action="continue to analysis",
            )
        )
        await self.announce(
            recipient=AgentRole.ANALYSIS,
            reason=f"browser step skipped: {reason}",
            result={"skipped": True, "reason": reason},
            confidence=1.0,
        )
        return [], []
