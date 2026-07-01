"""Network-agent tests — hermetic (no network, no external deps).

Three layers, mirroring ``tests/test_active_recon.py``:

* **Detectors** — the pure helpers in ``network.detectors`` (JWT decode, endpoint
  classification, WebSocket + CORS detection) exercised directly over canned input.
* **Modules** — the concrete ``NetworkModule``s run over a hand-built
  ``NetworkContext`` snapshot; deterministic and dependency-free.
* **Pipeline** — the disabled-by-default no-op and a stubbed end-to-end run proving
  network assets reach the graph, become findings, and render a report section.
"""

from __future__ import annotations

import base64
import json

import pytest

from recon_platform.agents.network import NetworkAgent
from recon_platform.bootstrap import build_container
from recon_platform.core.config import Settings
from recon_platform.domain.enums import AgentRole, AssetType, RelationType
from recon_platform.domain.schemas import Asset, EngagementContext, ReconResult
from recon_platform.network.base import NetworkContext
from recon_platform.network.detectors import (
    classify_api_endpoint,
    cors_issues,
    decode_jwt,
    find_jwts,
    websocket_endpoints,
)
from recon_platform.network.modules import (
    APIClassificationModule,
    CORSHygieneModule,
    JWTInspectionModule,
    WebSocketReviewModule,
    build_network_modules,
)
from recon_platform.orchestration.graph import ReconOrchestrator
from recon_platform.plugins.network import NetworkModuleTool, NetworkPlugin
from recon_platform.recon.base import ReconModule


# ---------------------------------------------------------------------------
# Helpers — build deterministic JWTs (unsigned; inspection only).
# ---------------------------------------------------------------------------
def _b64(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


def _make_jwt(header: dict, payload: dict) -> str:
    return f"{_b64(header)}.{_b64(payload)}.c2lnbmF0dXJlc2ln"


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------
def test_decode_jwt_flags_alg_none():
    token = _make_jwt({"alg": "none", "typ": "JWT"}, {"sub": "1", "exp": 9999999999})
    decoded = decode_jwt(token)
    assert decoded is not None
    assert decoded.alg == "none"
    assert any("alg=none" in i for i in decoded.issues)


def test_decode_jwt_flags_missing_exp_and_sensitive_claims():
    token = _make_jwt({"alg": "RS256"}, {"email": "a@b.com", "role": "admin"})
    decoded = decode_jwt(token)
    assert decoded is not None
    assert any("never expires" in i for i in decoded.issues)
    assert any("sensitive claim" in i for i in decoded.issues)


def test_decode_jwt_flags_expired_with_injected_now():
    token = _make_jwt({"alg": "RS256"}, {"exp": 1000})
    decoded = decode_jwt(token, now=2000)
    assert decoded is not None and any("expired" in i for i in decoded.issues)


def test_decode_jwt_rejects_non_jwt():
    assert decode_jwt("not.a.jwt") is None
    assert decode_jwt("eyJ-only-one-part") is None


def test_find_jwts_extracts_distinct_tokens():
    a = _make_jwt({"alg": "none"}, {"a": 1})
    b = _make_jwt({"alg": "RS256"}, {"b": 2})
    found = find_jwts(f"Authorization: Bearer {a}\nx-other: {b} {a}")
    assert set(found) == {a, b}


def test_classify_api_endpoint():
    assert classify_api_endpoint("https://x.com/graphql") == "graphql"
    assert classify_api_endpoint("https://x.com/api/v1/users") == "rest"
    assert classify_api_endpoint("https://x.com/v2/orders") == "rest"
    assert classify_api_endpoint("https://x.com/data.json") == "rest"
    assert classify_api_endpoint("https://x.com/about") is None


def test_websocket_endpoints_detects_scheme():
    pairs = websocket_endpoints("connect ws://x.com/live and wss://x.com/secure")
    assert ("ws://x.com/live", False) in pairs
    assert ("wss://x.com/secure", True) in pairs


def test_cors_issues_wildcard_and_credentials():
    assert cors_issues("access-control-allow-origin", "*", credentialed=False)
    creds = cors_issues("access-control-allow-origin", "*", credentialed=True)
    assert any("credentials" in i for i in creds)
    assert cors_issues("access-control-allow-origin", "null", credentialed=False)
    assert cors_issues("content-type", "text/html", credentialed=True) == []


# ---------------------------------------------------------------------------
# Modules
# ---------------------------------------------------------------------------
def _header(name: str, value: str) -> Asset:
    return Asset(
        type=AssetType.HEADER,
        value=f"{name}: {value}",
        source="http_headers",
        attributes={"name": name.lower(), "value": value},
    )


async def test_jwt_module_emits_assets_and_relations():
    token = _make_jwt({"alg": "none"}, {"sub": "1"})
    secret = Asset(type=AssetType.SECRET, value=token, source="ocr")
    ctx = NetworkContext("example.com", Settings(), tokens=[secret])
    res = await JWTInspectionModule().run(ctx)
    jwts = [a for a in res.assets if a.type == AssetType.JWT]
    assert jwts and jwts[0].attributes["alg"] == "none"
    assert jwts[0].attributes["issues"]
    assert all(r.type == RelationType.CONTAINS for r in res.relations)


async def test_api_classification_module():
    ep = Asset(type=AssetType.ENDPOINT, value="https://example.com/graphql", source="katana")
    ctx = NetworkContext("example.com", Settings(), endpoints=[ep])
    res = await APIClassificationModule().run(ctx)
    apis = [a for a in res.assets if a.type == AssetType.API_ENDPOINT]
    assert apis and apis[0].attributes["api_type"] == "graphql"
    assert apis[0].attributes.get("introspection_risk") is True


async def test_websocket_module_flags_insecure():
    ep = Asset(type=AssetType.URL, value="ws://example.com/live", source="browser")
    ctx = NetworkContext("example.com", Settings(), endpoints=[ep])
    res = await WebSocketReviewModule().run(ctx)
    ws = [a for a in res.assets if a.type == AssetType.WEBSOCKET]
    assert ws and ws[0].attributes["secure"] is False


async def test_cors_module_merges_issue_onto_header_key():
    acao = _header("Access-Control-Allow-Origin", "*")
    acac = _header("Access-Control-Allow-Credentials", "true")
    ctx = NetworkContext("example.com", Settings(), headers=[acao, acac])
    res = await CORSHygieneModule().run(ctx)
    # Re-emitted with the SAME key so the graph merges cors_issues onto the header.
    assert res.assets and res.assets[0].key == acao.key
    assert res.assets[0].attributes["cors_issues"]
    assert any("credentials" in i for i in res.assets[0].attributes["cors_issues"])


def test_build_network_modules_honours_toggles():
    settings = Settings()
    settings.network.decode_jwt = False
    settings.network.classify_apis = False
    settings.network.flag_insecure_websocket = False
    names = {m.name for m in build_network_modules(settings)}
    assert names == {"cors_hygiene"}  # CORS always on; the rest gated off
    assert len(build_network_modules(Settings())) == 4  # defaults: all on


def test_plugin_exposes_network_modules():
    factory = lambda: NetworkContext("example.com", Settings())  # noqa: E731
    plugin = NetworkPlugin(build_network_modules(Settings()), factory)
    names = {t.name for t in plugin.tools()}
    assert "network.jwt_inspection" in names and "network.cors_hygiene" in names


async def test_plugin_tool_run_returns_result_shape():
    factory = lambda: NetworkContext("example.com", Settings())  # noqa: E731
    out = await NetworkModuleTool(JWTInspectionModule(), factory).run(target="example.com")
    assert set(out) >= {"assets", "relations", "notes", "errors"}


# ---------------------------------------------------------------------------
# Pipeline — disabled no-op + stubbed end-to-end run
# ---------------------------------------------------------------------------
class _StubReconModule(ReconModule):
    """Offline stub seeding the graph with network-relevant assets."""

    name = "stub"
    description = "offline stub"

    async def run(self, ctx) -> ReconResult:  # noqa: ANN001
        token = _make_jwt({"alg": "none"}, {"sub": "1"})
        return ReconResult(
            task_id="",
            module=self.name,
            assets=[
                Asset(type=AssetType.DOMAIN, value=ctx.target, source="stub"),
                _header("Access-Control-Allow-Origin", "*"),
                _header("Access-Control-Allow-Credentials", "true"),
                Asset(type=AssetType.SECRET, value=token, source="stub"),
                Asset(
                    type=AssetType.ENDPOINT,
                    value="https://example.com/graphql",
                    source="stub",
                ),
                Asset(type=AssetType.URL, value="ws://example.com/live", source="stub"),
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


async def test_network_disabled_by_default_is_noop():
    settings = _base_settings()
    assert settings.network.enabled is False
    orch = ReconOrchestrator(build_container(settings))

    bundle = await orch.run(EngagementContext(target="example.com"))

    assert not any(a.type == AssetType.JWT for a in bundle.assets)
    assert not any(t.agent == AgentRole.NETWORK for t in bundle.traces)
    assert bundle.plan is not None and len(bundle.plan.tasks) == 3


async def test_network_enabled_runs_and_reports():
    settings = _base_settings()
    settings.network.enabled = True
    orch = ReconOrchestrator(build_container(settings))

    bundle = await orch.run(EngagementContext(target="example.com"))

    # Network assets reached the knowledge graph.
    assert any(a.type == AssetType.JWT for a in bundle.assets)
    assert any(a.type == AssetType.API_ENDPOINT for a in bundle.assets)
    assert any(a.type == AssetType.WEBSOCKET for a in bundle.assets)
    assert any(a.attributes.get("cors_issues") for a in bundle.assets)

    titles = [f.title.lower() for f in bundle.findings]
    assert any("json web token" in t for t in titles)
    assert any("cors" in t for t in titles)
    assert any("websocket" in t for t in titles)

    from recon_platform.reporting.renderers import get_renderer

    md = get_renderer("markdown").render(bundle)
    assert "Network Analysis" in md

    # Plan is untouched (still the canonical 3-task passive plan).
    assert bundle.plan is not None and len(bundle.plan.tasks) == 3


async def test_network_agent_skips_when_disabled():
    from recon_platform.domain.interfaces import (
        KnowledgeGraph,
        LLMProvider,
        Memory,
        MessageBus,
    )

    settings = _base_settings()
    container = build_container(settings)
    agent = NetworkAgent(
        container.resolve(MessageBus),  # type: ignore[type-abstract]
        container.resolve(Memory),  # type: ignore[type-abstract]
        container.resolve(LLMProvider),  # type: ignore[type-abstract]
        container.resolve(KnowledgeGraph),  # type: ignore[type-abstract]
        settings,
    )
    assets, relations = await agent.run_network(EngagementContext(target="example.com"))
    assert assets == [] and relations == []
