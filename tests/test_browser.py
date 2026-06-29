"""Browser-agent tests — hermetic (no real Chromium, Playwright not required).

Mirrors ``tests/test_pipeline.py``: the passive recon modules are stubbed offline,
and the browser session + modules are stubbed via monkeypatch so nothing launches
a browser and Playwright is never imported. We assert three behaviours:

* **disabled by default** — the browser step no-ops; the plan stays 3 tasks.
* **enabled (stubbed)** — browser assets land in the graph and drive findings.
* **graceful degradation** — enabled but Playwright absent → clean skip + trace.
"""

from __future__ import annotations

import pytest

from recon_platform.bootstrap import build_container
from recon_platform.browser.base import BrowserModule
from recon_platform.core.config import Settings
from recon_platform.domain.enums import AgentRole, AssetType
from recon_platform.domain.schemas import Asset, EngagementContext, ReconResult
from recon_platform.orchestration.graph import ReconOrchestrator
from recon_platform.recon.base import ReconModule


class _StubReconModule(ReconModule):
    name = "stub"
    description = "offline stub"

    async def run(self, ctx) -> ReconResult:  # noqa: ANN001
        return ReconResult(
            task_id="",
            module=self.name,
            assets=[Asset(type=AssetType.DOMAIN, value=ctx.target, source="stub")],
            notes=["stub ran"],
        )


class _StubBrowserModule(BrowserModule):
    name = "stub_browser"
    description = "offline browser stub"

    async def run(self, ctx) -> ReconResult:  # noqa: ANN001
        return ReconResult(
            task_id="",
            module=self.name,
            assets=[
                Asset(
                    type=AssetType.URL,
                    value="https://example.com/",
                    source="stub_browser",
                    attributes={
                        "via": "browser",
                        "title": "Example Domain",
                        "screenshot": "reports/screenshots/example.com.png",
                    },
                ),
                Asset(
                    type=AssetType.COOKIE,
                    value="session",
                    source="stub_browser",
                    attributes={"secure": False, "http_only": False, "same_site": "None"},
                ),
                Asset(
                    type=AssetType.JS_FILE,
                    value="https://example.com/app.js",
                    source="stub_browser",
                ),
            ],
            notes=["stub browser ran"],
        )


class _FakeSession:
    """Async-context-manager stand-in for BrowserSession (never touches Playwright)."""

    page = None
    requests: list = []
    response_headers: dict = {}
    recovery_notes: list = []

    def __init__(self, settings) -> None:  # noqa: ANN001
        self._settings = settings

    async def __aenter__(self) -> _FakeSession:
        return self

    async def __aexit__(self, *exc) -> None:  # noqa: ANN002
        return None


@pytest.fixture(autouse=True)
def _patch_recon_modules(monkeypatch):
    """Keep the recon step offline for every test in this module."""
    factory = lambda: [_StubReconModule()]  # noqa: E731
    monkeypatch.setattr("recon_platform.agents.recon.build_passive_modules", factory)
    monkeypatch.setattr("recon_platform.agents.planner.build_passive_modules", factory)


def _disabled_settings() -> Settings:
    settings = Settings(authorized_only=False)
    settings.llm.enabled = False
    return settings


def _enabled_settings() -> Settings:
    settings = _disabled_settings()
    settings.browser.enabled = True
    return settings


async def test_browser_disabled_by_default_is_noop():
    settings = _disabled_settings()
    assert settings.browser.enabled is False
    container = build_container(settings)
    orch = ReconOrchestrator(container)

    bundle = await orch.run(EngagementContext(target="example.com"))

    # Plan unchanged (3 tasks) and no browser-sourced assets.
    assert bundle.plan is not None and len(bundle.plan.tasks) == 3
    assert not any(a.attributes.get("via") == "browser" for a in bundle.assets)
    assert not any(a.type == AssetType.COOKIE for a in bundle.assets)


async def test_browser_enabled_stubbed_produces_assets_and_findings(monkeypatch):
    monkeypatch.setattr("recon_platform.agents.browser.playwright_available", lambda: True)
    monkeypatch.setattr("recon_platform.agents.browser.BrowserSession", _FakeSession)
    monkeypatch.setattr(
        "recon_platform.agents.browser.build_browser_modules",
        lambda: [_StubBrowserModule()],
    )

    container = build_container(_enabled_settings())
    orch = ReconOrchestrator(container)

    bundle = await orch.run(EngagementContext(target="example.com"))

    # Browser assets reached the knowledge graph.
    assert any(a.type == AssetType.COOKIE for a in bundle.assets)
    assert any(a.type == AssetType.JS_FILE for a in bundle.assets)
    assert any(a.attributes.get("via") == "browser" for a in bundle.assets)

    # Insecure-cookie finding fired.
    assert any("security attributes" in f.title.lower() for f in bundle.findings)

    # Browser-capture finding carries screenshot evidence.
    capture = next(f for f in bundle.findings if "browser capture" in f.title.lower())
    assert any(e.data.get("screenshot") for e in capture.evidence)

    # Plan still a clean 3 tasks (browser runs independently of the plan).
    assert bundle.plan is not None and len(bundle.plan.tasks) == 3


async def test_browser_graceful_degradation_when_playwright_missing(monkeypatch):
    # Enabled, but Playwright is "not installed".
    monkeypatch.setattr("recon_platform.agents.browser.playwright_available", lambda: False)

    container = build_container(_enabled_settings())
    orch = ReconOrchestrator(container)

    # Must not raise.
    bundle = await orch.run(EngagementContext(target="example.com"))

    # A skip trace was recorded by the browser agent.
    skips = [
        t
        for t in bundle.traces
        if t.agent == AgentRole.BROWSER and t.action == "skip"
    ]
    assert skips, "expected a browser skip trace"
    # No browser assets were produced.
    assert not any(a.attributes.get("via") == "browser" for a in bundle.assets)
