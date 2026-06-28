"""End-to-end orchestration test — hermetic (no network, no LLM).

Replaces the passive modules with an offline stub so the full
Plan → Recon → Analyze → Report pipeline runs deterministically and we can
assert the report bundle and rendered output.
"""

from __future__ import annotations

import pytest

from recon_platform.bootstrap import build_container
from recon_platform.core.config import Settings
from recon_platform.domain.enums import AssetType
from recon_platform.domain.schemas import Asset, EngagementContext, ReconResult
from recon_platform.orchestration.graph import ReconOrchestrator
from recon_platform.recon.base import ReconModule
from recon_platform.reporting.renderers import get_renderer


class _StubModule(ReconModule):
    name = "stub"
    description = "offline stub"

    async def run(self, ctx) -> ReconResult:  # noqa: ANN001
        return ReconResult(
            task_id="",
            module=self.name,
            assets=[
                Asset(
                    type=AssetType.HEADER,
                    value="server: nginx/1.25",
                    source="stub",
                    attributes={"name": "server", "value": "nginx/1.25"},
                ),
                Asset(type=AssetType.TECHNOLOGY, value="nginx", source="stub"),
                Asset(type=AssetType.SUBDOMAIN, value="api.example.com", source="stub"),
            ],
            notes=["stub ran"],
        )


@pytest.fixture(autouse=True)
def _patch_modules(monkeypatch):
    factory = lambda: [_StubModule()]  # noqa: E731
    monkeypatch.setattr("recon_platform.agents.recon.build_passive_modules", factory)
    monkeypatch.setattr("recon_platform.agents.planner.build_passive_modules", factory)


async def test_full_pipeline_offline_produces_report():
    settings = Settings(authorized_only=False)
    settings.llm.enabled = False  # force deterministic path
    container = build_container(settings)
    orch = ReconOrchestrator(container)

    bundle = await orch.run(EngagementContext(target="example.com"))

    assert bundle is not None
    assert bundle.engagement.authorized is True
    # stub seeded a header missing security headers + a technology asset
    assert any("security headers" in f.title.lower() for f in bundle.findings)
    assert any(a.type == AssetType.TECHNOLOGY for a in bundle.assets)
    assert bundle.plan is not None and len(bundle.plan.tasks) == 3

    # Reasoning trace captured across agents
    agents_seen = {t.agent for t in bundle.traces}
    assert len(agents_seen) >= 3

    # Renderers produce non-empty output in every format
    for fmt in ("markdown", "html", "json"):
        out = get_renderer(fmt).render(bundle)
        assert "example.com" in out
        assert len(out) > 100


async def test_event_stream_emits_lifecycle():
    settings = Settings(authorized_only=False)
    settings.llm.enabled = False
    container = build_container(settings)
    orch = ReconOrchestrator(container)

    import asyncio

    events: list[str] = []

    async def consume():
        async for ev in orch.stream_events():
            events.append(ev["event"])

    consumer = asyncio.create_task(consume())
    await orch.run(EngagementContext(target="example.com"))
    await asyncio.wait_for(consumer, timeout=5)

    assert "run.start" in events
    assert "run.complete" in events
    assert "step" in events
