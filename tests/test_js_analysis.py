"""JavaScript-analysis tests — hermetic (no real network; fetch is mocked).

Three layers, mirroring ``tests/test_api_discovery.py``:

* **Analyzers** — the pure helpers in ``js_analysis.analyzers`` (endpoint /
  parameter extraction, source-map discovery) exercised over canned script text.
* **Modules** — the concrete ``JSModule``s run over a hand-built ``JSContext``;
  deterministic and dependency-free.
* **Pipeline** — the disabled-by-default no-op and a stubbed end-to-end run
  (``fetch_js`` monkeypatched to return canned bodies) proving JS assets reach the
  graph, become findings, and render a report section.
"""

from __future__ import annotations

import pytest

from recon_platform.agents.js_analysis import JSAnalysisAgent
from recon_platform.bootstrap import build_container
from recon_platform.core.config import Settings
from recon_platform.domain.enums import AgentRole, AssetType, RelationType
from recon_platform.domain.schemas import Asset, EngagementContext, ReconResult
from recon_platform.js_analysis.analyzers import (
    extract_endpoints,
    extract_parameters,
    find_source_maps,
    is_internal_url,
)
from recon_platform.js_analysis.base import JSContext
from recon_platform.js_analysis.modules import (
    EndpointExtractionModule,
    SecretDetectionModule,
    SourceMapDiscoveryModule,
    build_js_modules,
)
from recon_platform.orchestration.graph import ReconOrchestrator
from recon_platform.plugins.js_analysis import JSAnalysisPlugin, JSModuleTool
from recon_platform.recon.base import ReconModule

_SAMPLE_JS = (
    'const API = "https://example.com/api/v1";\n'
    'fetch("/api/v1/orders?status=open");\n'
    'axios.get("/users/42");\n'
    'const bg = "/img/logo.png";\n'  # static → filtered
    'const key = "AKIAIOSFODNN7EXAMPLE";\n'
    "//# sourceMappingURL=app.min.js.map\n"
)


# ---------------------------------------------------------------------------
# Analyzers
# ---------------------------------------------------------------------------
def test_extract_endpoints_resolves_and_filters():
    eps = extract_endpoints(_SAMPLE_JS, base_url="https://example.com/static/app.js")
    assert "https://example.com/api/v1" in eps
    assert "https://example.com/api/v1/orders?status=open" in eps
    assert "https://example.com/users/42" in eps
    assert not any(e.endswith("logo.png") for e in eps)  # static filtered


def test_extract_parameters_from_query():
    params = extract_parameters(_SAMPLE_JS, base_url="https://example.com/static/app.js")
    assert any(p["name"] == "status" and p["location"] == "query" for p in params)


def test_find_source_maps_resolves_relative():
    maps = find_source_maps(_SAMPLE_JS, base_url="https://example.com/static/app.js")
    assert maps == ["https://example.com/static/app.min.js.map"]


def test_find_source_maps_skips_data_uri():
    assert find_source_maps("//# sourceMappingURL=data:application/json;base64,xx") == []


def test_is_internal_url():
    assert is_internal_url("https://api.example.com/x", "example.com") is True
    assert is_internal_url("https://example.com/x", "example.com") is True
    assert is_internal_url("https://evil.com/x", "example.com") is False


# ---------------------------------------------------------------------------
# Modules
# ---------------------------------------------------------------------------
def _ctx(sources: dict[str, str], target: str = "example.com") -> JSContext:
    return JSContext(target, Settings(), sources=sources)


async def test_endpoint_module_emits_endpoints_and_params():
    ctx = _ctx({"https://example.com/static/app.js": _SAMPLE_JS})
    res = await EndpointExtractionModule().run(ctx)
    eps = [a for a in res.assets if a.type == AssetType.ENDPOINT]
    params = [a for a in res.assets if a.type == AssetType.API_PARAMETER]
    assert eps and all(a.attributes["via"] == "js" for a in eps)
    assert any(a.attributes.get("internal") for a in eps)
    assert params and all(a.attributes["via"] == "js" for a in params)
    assert any(r.type == RelationType.REFERENCES for r in res.relations)


async def test_secret_module_detects_aws_key():
    ctx = _ctx({"https://example.com/static/app.js": _SAMPLE_JS})
    res = await SecretDetectionModule().run(ctx)
    secrets = [a for a in res.assets if a.type == AssetType.SECRET]
    assert secrets and secrets[0].attributes["kind"] == "aws_access_key"
    assert secrets[0].attributes["via"] == "js"
    assert any(r.type == RelationType.CONTAINS for r in res.relations)


async def test_source_map_module():
    ctx = _ctx({"https://example.com/static/app.js": _SAMPLE_JS})
    res = await SourceMapDiscoveryModule().run(ctx)
    maps = [a for a in res.assets if a.type == AssetType.SOURCE_MAP]
    assert maps and maps[0].value.endswith("app.min.js.map")


def test_build_js_modules_honours_toggles():
    settings = Settings()
    settings.js_analysis.extract_secrets = False
    settings.js_analysis.discover_source_maps = False
    names = {m.name for m in build_js_modules(settings)}
    assert names == {"js_endpoints"}
    assert len(build_js_modules(Settings())) == 3


def test_plugin_exposes_js_modules_and_accepts_sources():
    factory = lambda: JSContext("example.com", Settings())  # noqa: E731
    plugin = JSAnalysisPlugin(build_js_modules(Settings()), factory)
    assert {"js.js_endpoints", "js.js_secrets"} <= {t.name for t in plugin.tools()}


async def test_plugin_tool_run_accepts_inline_sources():
    factory = lambda: JSContext("example.com", Settings())  # noqa: E731
    out = await JSModuleTool(SecretDetectionModule(), factory).run(
        sources={"https://example.com/a.js": "AKIAIOSFODNN7EXAMPLE"}
    )
    assert set(out) >= {"assets", "relations", "notes", "errors"}
    assert any(a["type"] == "secret" for a in out["assets"])


# ---------------------------------------------------------------------------
# Pipeline — disabled no-op + stubbed end-to-end run (fetch mocked)
# ---------------------------------------------------------------------------
class _StubReconModule(ReconModule):
    """Offline stub seeding the graph with a JS_FILE asset."""

    name = "stub"
    description = "offline stub"

    async def run(self, ctx) -> ReconResult:  # noqa: ANN001
        return ReconResult(
            task_id="",
            module=self.name,
            assets=[
                Asset(type=AssetType.DOMAIN, value=ctx.target, source="stub"),
                Asset(
                    type=AssetType.JS_FILE,
                    value="https://example.com/static/app.js",
                    source="stub",
                ),
            ],
            notes=["stub ran"],
        )


@pytest.fixture(autouse=True)
def _patch_recon_modules(monkeypatch):
    factory = lambda: [_StubReconModule()]  # noqa: E731
    monkeypatch.setattr("recon_platform.agents.recon.build_passive_modules", factory)
    monkeypatch.setattr("recon_platform.agents.planner.build_passive_modules", factory)


def _base_settings() -> Settings:
    settings = Settings(authorized_only=False)
    settings.llm.enabled = False
    return settings


async def test_js_disabled_by_default_is_noop():
    settings = _base_settings()
    assert settings.js_analysis.enabled is False
    orch = ReconOrchestrator(build_container(settings))

    bundle = await orch.run(EngagementContext(target="example.com"))

    assert not any(a.type == AssetType.SOURCE_MAP for a in bundle.assets)
    assert not any(t.agent == AgentRole.JS_ANALYSIS for t in bundle.traces)
    assert bundle.plan is not None and len(bundle.plan.tasks) == 3


async def test_js_enabled_runs_and_reports(monkeypatch):
    async def _fake_fetch(client, url, *, max_bytes=2_000_000):  # noqa: ANN001
        return _SAMPLE_JS if url.endswith("app.js") else None

    monkeypatch.setattr("recon_platform.agents.js_analysis.fetch_js", _fake_fetch)

    settings = _base_settings()
    settings.js_analysis.enabled = True
    orch = ReconOrchestrator(build_container(settings))

    bundle = await orch.run(EngagementContext(target="example.com"))

    assert any(
        a.type == AssetType.ENDPOINT and a.attributes.get("via") == "js"
        for a in bundle.assets
    )
    assert any(
        a.type == AssetType.SECRET and a.attributes.get("via") == "js" for a in bundle.assets
    )
    assert any(a.type == AssetType.SOURCE_MAP for a in bundle.assets)

    titles = [f.title.lower() for f in bundle.findings]
    assert any("secrets embedded in javascript" in t for t in titles)
    assert any("source maps exposed" in t for t in titles)

    from recon_platform.reporting.renderers import get_renderer

    md = get_renderer("markdown").render(bundle)
    assert "JavaScript Analysis" in md
    assert bundle.plan is not None and len(bundle.plan.tasks) == 3


async def test_js_agent_skips_when_disabled():
    from recon_platform.domain.interfaces import (
        KnowledgeGraph,
        LLMProvider,
        Memory,
        MessageBus,
    )

    settings = _base_settings()
    container = build_container(settings)
    agent = JSAnalysisAgent(
        container.resolve(MessageBus),  # type: ignore[type-abstract]
        container.resolve(Memory),  # type: ignore[type-abstract]
        container.resolve(LLMProvider),  # type: ignore[type-abstract]
        container.resolve(KnowledgeGraph),  # type: ignore[type-abstract]
        settings,
    )
    assets, relations = await agent.run_js_analysis(EngagementContext(target="example.com"))
    assert assets == [] and relations == []
