"""Authentication agent — drives auth workflows and captures sessions.

The Phase-9 counterpart to the Browser agent, but **active/intrusive**: it submits
credentials. It discovers candidate login / registration / forgot-password / admin
URLs from the knowledge graph, opens a real browser via the
:func:`~recon_platform.auth.page.open_auth_page` seam, runs the configured
workflows, captures any authenticated session (cookies) into episodic memory for
downstream reuse, records a masked reasoning trace per workflow, and emits
``auth.*`` events on the A2A bus.

It is **opt-in and self-degrading** behind a *two-key* posture: it runs only when
``settings.auth.enabled`` **and** ``settings.auth.authorized`` are set **and** the
target passes the authorization gate. Any other state — or no browser available —
records a clean skip and returns empty. Credentials are held as ``SecretStr`` and
are masked everywhere they surface; cookie *values* live only in episodic memory,
never on the graph asset or in the report.
"""

from __future__ import annotations

from dataclasses import asdict

from recon_platform.agents.base import BaseAgent
from recon_platform.auth.credentials import credentials_from_settings
from recon_platform.auth.discovery import (
    candidate_admin_urls,
    candidate_forgot_urls,
    candidate_login_urls,
    candidate_register_urls,
)
from recon_platform.auth.models import AuthResult
from recon_platform.auth.page import open_auth_page
from recon_platform.auth.workflows import build_workflows
from recon_platform.core.config import Settings
from recon_platform.core.exceptions import UnauthorizedTargetError
from recon_platform.domain.enums import AgentRole, AssetType, MemoryScope
from recon_platform.domain.interfaces import KnowledgeGraph, LLMProvider, Memory, MessageBus
from recon_platform.domain.schemas import Asset, EngagementContext, ReasoningTrace, Relation
from recon_platform.recon.authorization import ensure_authorized


class AuthenticationAgent(BaseAgent):
    def __init__(
        self,
        bus: MessageBus,
        memory: Memory,
        llm: LLMProvider,
        graph: KnowledgeGraph,
        settings: Settings,
    ) -> None:
        super().__init__(AgentRole.AUTHENTICATION, bus, memory, llm)
        self.graph = graph
        self.settings = settings

    async def run_auth(
        self, engagement: EngagementContext
    ) -> tuple[list[Asset], list[Relation]]:
        # -- authorization (two keys) + graceful skip ------------------------
        auth = self.settings.auth
        if not auth.enabled:
            return await self._skip("auth disabled (settings.auth.enabled=False)")
        if not auth.authorized:
            return await self._skip(
                "auth not authorized (set settings.auth.authorized=True to acknowledge "
                "you are permitted to submit credentials to this target)"
            )
        try:
            ensure_authorized(engagement.target, self.settings)
        except UnauthorizedTargetError as exc:
            return await self._skip(f"target failed authorization gate: {exc}")

        creds = credentials_from_settings(self.settings)
        workflows = build_workflows(self.settings)
        all_assets: list[Asset] = []

        await self.announce(
            recipient=AgentRole.ANALYSIS,
            reason="auth.started",
            result={"workflows": [w.name for w in workflows], "credentials": creds.masked()},
            confidence=0.9,
        )

        async with open_auth_page(self.settings) as page:
            if page is None:
                return await self._skip("no browser backend available (pip install '.[browser]')")

            for workflow in workflows:
                urls = self._urls_for(workflow.name)
                self.log.info("auth.workflow.start", workflow=workflow.name, urls=len(urls))
                results = await workflow.run(page, creds, urls, self.settings)
                for result in results:
                    asset = self._asset_for(result)
                    self.graph.add_asset(asset)
                    all_assets.append(asset)
                    if result.session is not None:
                        # Cookie values are sensitive → episodic memory only.
                        await self.memory.remember(
                            MemoryScope.EPISODIC,
                            f"auth_session:{engagement.id}:{result.workflow}:{result.url}",
                            asdict(result.session),
                        )
                await self._record_workflow(workflow.name, results)

        await self.announce(
            recipient=AgentRole.ANALYSIS,
            reason="auth.completed",
            result={"sessions": len(all_assets)},
            confidence=0.9,
        )
        self.log.info("auth.complete", sessions=len(all_assets))
        return all_assets, []

    # -- helpers ------------------------------------------------------------
    def _urls_for(self, workflow: str) -> list[str]:
        auth = self.settings.auth
        assets = self.graph.assets(AssetType.URL) + self.graph.assets(AssetType.ENDPOINT)
        limit = max(1, auth.max_urls)
        if workflow == "login":
            return candidate_login_urls(assets, explicit=auth.login_url, limit=limit)
        if workflow == "registration":
            return candidate_register_urls(assets, explicit=auth.register_url, limit=limit)
        if workflow == "forgot_password":
            return candidate_forgot_urls(assets, limit=limit)
        if workflow == "admin_probe":
            return candidate_admin_urls(assets, limit=limit)
        return []

    def _asset_for(self, result: AuthResult) -> Asset:
        """Build a masked SESSION asset (never carries cookie values)."""
        names = result.session.cookie_names if result.session else []
        return Asset(
            type=AssetType.SESSION,
            value=f"{result.workflow}:{result.url or 'n/a'}",
            source=self.role.value,
            attributes={
                "workflow": result.workflow,
                "url": result.url,
                "success": result.success,
                "scheme": result.scheme,
                "reason": result.reason,
                "cookie_names": names,
                "authenticated": bool(result.session),
                **result.detail,
            },
            confidence=0.8 if result.success else 0.5,
        )

    async def _record_workflow(self, name: str, results: list[AuthResult]) -> None:
        successes = [r for r in results if r.success]
        errors = [r.error for r in results if r.error]
        await self.record(
            ReasoningTrace(
                agent=self.role,
                action=f"workflow:{name}",
                observation=f"{len(results)} attempt(s) across candidate URLs",
                result=(
                    f"{len(successes)} succeeded"
                    + (f"; sessions captured: {len(successes)}" if successes else "")
                ),
                reflection="; ".join(errors) or "no errors",
                confidence=0.5 if errors else 0.85,
                recovery_plan="verify credentials / login URL" if not successes else "",
            )
        )
        await self.announce(
            recipient=AgentRole.ANALYSIS,
            reason=f"auth.{name}",
            result={
                "workflow": name,
                "attempts": len(results),
                "successes": len(successes),
            },
            confidence=0.5 if errors else 0.85,
        )

    async def _skip(self, reason: str) -> tuple[list[Asset], list[Relation]]:
        """Record + announce a clean skip and return empty results."""
        self.log.info("auth.skip", reason=reason)
        await self.record(
            ReasoningTrace(
                agent=self.role,
                action="skip",
                observation=reason,
                result="auth step skipped",
                reflection="graceful degradation / safety gate — pipeline unaffected",
                confidence=1.0,
                next_action="continue to analysis",
            )
        )
        await self.announce(
            recipient=AgentRole.ANALYSIS,
            reason=f"auth.skipped: {reason}",
            result={"skipped": True, "reason": reason},
            confidence=1.0,
        )
        return [], []
