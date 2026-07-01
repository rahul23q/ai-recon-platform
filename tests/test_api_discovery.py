"""API-discovery tests — hermetic (no network, no external deps).

Three layers, mirroring ``tests/test_network.py``:

* **Detectors** — the pure helpers in ``api_discovery.detectors`` (style
  classification, REST signature parsing, parameter extraction, auth-scheme
  detection, OpenAPI parsing) exercised directly over canned input.
* **Modules** — the concrete ``APIModule``s run over a hand-built
  ``APIDiscoveryContext`` snapshot; deterministic and dependency-free.
* **Pipeline** — the disabled-by-default no-op and a stubbed end-to-end run proving
  API assets reach the graph, become findings, and render a report section.
"""

from __future__ import annotations

import pytest

from recon_platform.agents.api_discovery import APIDiscoveryAgent
from recon_platform.api_discovery.base import APIDiscoveryContext
from recon_platform.api_discovery.detectors import (
    api_style,
    detect_auth_schemes,
    extract_parameters,
    parse_openapi,
    rest_signature,
)
from recon_platform.api_discovery.modules import (
    AuthSchemeModule,
    GraphQLDiscoveryModule,
    RESTInferenceModule,
    SOAPGRPCDiscoveryModule,
    build_api_modules,
)
from recon_platform.bootstrap import build_container
from recon_platform.core.config import Settings
from recon_platform.domain.enums import AgentRole, AssetType, RelationType
from recon_platform.domain.schemas import Asset, EngagementContext, ReconResult
from recon_platform.orchestration.graph import ReconOrchestrator
from recon_platform.plugins.api_discovery import APIDiscoveryPlugin, APIModuleTool
from recon_platform.recon.base import ReconModule


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------
def test_api_style_classification():
    assert api_style("https://x.com/graphql") == "graphql"
    assert api_style("https://x.com/svc/Weather.asmx") == "soap"
    assert api_style("https://x.com/service?wsdl") == "soap"
    assert api_style("https://x.com/grpc-web/pkg.Service/Method") == "grpc"
    assert api_style("https://x.com/api/v2/users") == "rest"
    assert api_style("https://x.com/about") is None


def test_rest_signature_versioned():
    sig = rest_signature("https://x.com/api/v1/users/42")
    assert sig is not None
    assert sig["base_path"] == "/api/v1"
    assert sig["version"] == "v1"
    assert sig["resource"] == "users"


def test_rest_signature_api_anchor_without_version():
    sig = rest_signature("https://x.com/api/orders")
    assert sig is not None and sig["base_path"] == "/api" and sig["resource"] == "orders"


def test_rest_signature_none_without_anchor():
    assert rest_signature("https://x.com/data.json") is None


def test_extract_parameters_query_and_path():
    params = extract_parameters("https://x.com/api/v1/users/42?page=2&sort=asc")
    locs = {(p["name"], p["location"]) for p in params}
    assert ("page", "query") in locs
    assert ("sort", "query") in locs
    assert ("user_id", "path") in locs  # 42 → identifier under 'users'


def test_detect_auth_schemes():
    headers = [
        ("Authorization", "Bearer abc.def.ghi"),
        ("WWW-Authenticate", "Basic realm=x"),
        ("X-API-Key", "k"),
        ("Set-Cookie", "sid=1"),
    ]
    schemes = {s["scheme"] for s in detect_auth_schemes(headers)}
    assert {"bearer", "basic", "api_key", "cookie"} <= schemes


def test_parse_openapi():
    doc = '{"openapi":"3.0.0","info":{"title":"T","version":"1"},"paths":{"/a":{},"/b":{}}}'
    parsed = parse_openapi(doc)
    assert parsed is not None and parsed["title"] == "T"
    assert parsed["paths"] == ["/a", "/b"]
    assert parse_openapi("not json") is None
    assert parse_openapi('{"foo":1}') is None  # not an openapi doc


# ---------------------------------------------------------------------------
# Modules
# ---------------------------------------------------------------------------
def _endpoint(value: str) -> Asset:
    return Asset(type=AssetType.ENDPOINT, value=value, source="katana")


def _header(name: str, value: str) -> Asset:
    return Asset(
        type=AssetType.HEADER,
        value=f"{name}: {value}",
        source="http_headers",
        attributes={"name": name.lower(), "value": value},
    )


async def test_rest_module_groups_apis_and_params():
    ctx = APIDiscoveryContext(
        "x.com",
        Settings(),
        endpoints=[
            _endpoint("https://x.com/api/v1/users/42?page=2"),
            _endpoint("https://x.com/api/v1/orders"),
        ],
    )
    res = await RESTInferenceModule().run(ctx)
    apis = [a for a in res.assets if a.type == AssetType.API]
    params = [a for a in res.assets if a.type == AssetType.API_PARAMETER]
    assert len(apis) == 1  # grouped under x.com/api/v1
    assert set(apis[0].attributes["resources"]) == {"users", "orders"}
    assert apis[0].attributes["endpoint_count"] == 2
    assert any(p.attributes["location"] == "query" for p in params)
    assert any(r.type == RelationType.EXPOSES for r in res.relations)


async def test_graphql_module_uses_network_signal():
    api_ep = Asset(
        type=AssetType.API_ENDPOINT,
        value="https://x.com/graphql",
        source="network",
        attributes={"api_type": "graphql"},
    )
    ctx = APIDiscoveryContext("x.com", Settings(), api_endpoints=[api_ep])
    res = await GraphQLDiscoveryModule().run(ctx)
    apis = [a for a in res.assets if a.type == AssetType.API]
    assert apis and apis[0].attributes["style"] == "graphql"
    assert apis[0].attributes["introspection_risk"] is True


async def test_soap_grpc_module():
    ctx = APIDiscoveryContext(
        "x.com",
        Settings(),
        endpoints=[_endpoint("https://x.com/svc/Weather.asmx")],
    )
    res = await SOAPGRPCDiscoveryModule().run(ctx)
    apis = [a for a in res.assets if a.type == AssetType.API]
    assert apis and apis[0].attributes["style"] == "soap"


async def test_auth_module_emits_scheme_assets():
    ctx = APIDiscoveryContext(
        "x.com",
        Settings(),
        headers=[_header("Authorization", "Basic Zm9v")],
    )
    res = await AuthSchemeModule().run(ctx)
    schemes = {a.value for a in res.assets if a.type == AssetType.AUTH_SCHEME}
    assert "basic" in schemes


def test_build_api_modules_honours_toggles():
    settings = Settings()
    settings.api_discovery.discover_graphql = False
    settings.api_discovery.discover_soap_grpc = False
    names = {m.name for m in build_api_modules(settings)}
    assert names == {"rest_inference", "auth_scheme_detection"}
    assert len(build_api_modules(Settings())) == 4  # defaults: all on


def test_plugin_exposes_api_modules():
    factory = lambda: APIDiscoveryContext("x.com", Settings())  # noqa: E731
    plugin = APIDiscoveryPlugin(build_api_modules(Settings()), factory)
    names = {t.name for t in plugin.tools()}
    assert "api.rest_inference" in names and "api.auth_scheme_detection" in names


async def test_plugin_tool_run_returns_result_shape():
    factory = lambda: APIDiscoveryContext("x.com", Settings())  # noqa: E731
    out = await APIModuleTool(RESTInferenceModule(), factory).run(target="x.com")
    assert set(out) >= {"assets", "relations", "notes", "errors"}


# ---------------------------------------------------------------------------
# Pipeline — disabled no-op + stubbed end-to-end run
# ---------------------------------------------------------------------------
class _StubReconModule(ReconModule):
    """Offline stub seeding the graph with API-relevant assets."""

    name = "stub"
    description = "offline stub"

    async def run(self, ctx) -> ReconResult:  # noqa: ANN001
        return ReconResult(
            task_id="",
            module=self.name,
            assets=[
                Asset(type=AssetType.DOMAIN, value=ctx.target, source="stub"),
                _endpoint("https://example.com/api/v1/users/7?page=1"),
                _endpoint("https://example.com/api/v1/orders"),
                _endpoint("https://example.com/graphql"),
                _endpoint("https://example.com/legacy/Service.asmx"),
                _header("Authorization", "Basic Zm9vOmJhcg=="),
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


async def test_api_disabled_by_default_is_noop():
    settings = _base_settings()
    assert settings.api_discovery.enabled is False
    orch = ReconOrchestrator(build_container(settings))

    bundle = await orch.run(EngagementContext(target="example.com"))

    assert not any(a.type == AssetType.API for a in bundle.assets)
    assert not any(t.agent == AgentRole.API for t in bundle.traces)
    assert bundle.plan is not None and len(bundle.plan.tasks) == 3


async def test_api_enabled_runs_and_reports():
    settings = _base_settings()
    settings.api_discovery.enabled = True
    orch = ReconOrchestrator(build_container(settings))

    bundle = await orch.run(EngagementContext(target="example.com"))

    apis = [a for a in bundle.assets if a.type == AssetType.API]
    styles = {a.attributes.get("style") for a in apis}
    assert "rest" in styles and "graphql" in styles and "soap" in styles
    assert any(a.type == AssetType.AUTH_SCHEME and a.value == "basic" for a in bundle.assets)

    titles = [f.title.lower() for f in bundle.findings]
    assert any("api surface discovered" in t for t in titles)
    assert any("basic authentication" in t for t in titles)

    from recon_platform.reporting.renderers import get_renderer

    md = get_renderer("markdown").render(bundle)
    assert "API Discovery" in md

    assert bundle.plan is not None and len(bundle.plan.tasks) == 3


async def test_api_agent_skips_when_disabled():
    from recon_platform.domain.interfaces import (
        KnowledgeGraph,
        LLMProvider,
        Memory,
        MessageBus,
    )

    settings = _base_settings()
    container = build_container(settings)
    agent = APIDiscoveryAgent(
        container.resolve(MessageBus),  # type: ignore[type-abstract]
        container.resolve(Memory),  # type: ignore[type-abstract]
        container.resolve(LLMProvider),  # type: ignore[type-abstract]
        container.resolve(KnowledgeGraph),  # type: ignore[type-abstract]
        settings,
    )
    assets, relations = await agent.run_api_discovery(EngagementContext(target="example.com"))
    assert assets == [] and relations == []
