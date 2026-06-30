"""Active-recon tests — hermetic (no real binaries, no subprocess, no network).

Three layers, mirroring ``tests/test_desktop.py``:

* **Parsers** — each tool's ``parse`` is a pure function over canned stdout, so we
  exercise the ten wrappers directly with fixed output (no binary required) and
  assert the normalized assets/relations.
* **Framework** — the ``ToolExecution`` value object, the ``ExternalTool.run``
  skip path (binary absent) and parse path (a fake runner), ``binary_available``,
  and the plugin adapter are deterministic and dependency-free.
* **Pipeline** — the two-key authorization gate (disabled / unauthorized / failed
  engagement gate all skip cleanly) and a stubbed end-to-end run proving active
  assets reach the graph, become findings, and render a report section.
"""

from __future__ import annotations

import json

import pytest

from recon_platform.active_recon.base import ActiveToolContext, ExternalTool
from recon_platform.active_recon.models import ToolExecution
from recon_platform.active_recon.runner import ToolRunner, binary_available
from recon_platform.active_recon.tools import (
    ACTIVE_TOOLS,
    DirsearchTool,
    FfufTool,
    HttpxTool,
    NaabuTool,
    NmapTool,
    NucleiTool,
    SubfinderTool,
    build_active_tools,
)
from recon_platform.agents.active_recon import ActiveReconAgent
from recon_platform.bootstrap import build_container
from recon_platform.core.config import Settings
from recon_platform.domain.enums import AgentRole, AssetType, RelationType, ToolPermission
from recon_platform.domain.schemas import Asset, EngagementContext, ReconResult
from recon_platform.orchestration.graph import ReconOrchestrator
from recon_platform.plugins.active_recon import ActiveReconPlugin, ExternalToolTool
from recon_platform.recon.base import ReconModule

_NONEXISTENT_BINARY = "definitely-not-a-real-binary-xyz123"


# ---------------------------------------------------------------------------
# Parsers (pure functions over canned stdout)
# ---------------------------------------------------------------------------
def test_httpx_parses_urls_and_tech():
    out = (
        '{"url":"https://example.com","status_code":200,"title":"Ex","tech":["nginx"]}\n'
        "not json — ignored\n"
    )
    res = HttpxTool().parse(ToolExecution(tool="httpx", stdout=out), "example.com")
    urls = [a for a in res.assets if a.type == AssetType.URL]
    techs = [a for a in res.assets if a.type == AssetType.TECHNOLOGY]
    assert urls and urls[0].value == "https://example.com"
    assert urls[0].attributes["status_code"] == 200
    assert any(t.value == "nginx" for t in techs)


def test_subfinder_filters_out_of_scope_and_links():
    out = "www.example.com\napi.example.com\nattacker.com\n"
    res = SubfinderTool().parse(ToolExecution(tool="subfinder", stdout=out), "example.com")
    hosts = {a.value for a in res.assets if a.type == AssetType.SUBDOMAIN}
    assert "www.example.com" in hosts
    assert "api.example.com" in hosts
    assert "attacker.com" not in hosts  # out-of-scope dropped
    assert all(r.type == RelationType.SUBDOMAIN_OF for r in res.relations)


def test_naabu_parses_ports_with_exposes_relations():
    out = "example.com:80\nexample.com:443\ngarbage-line\n"
    res = NaabuTool().parse(ToolExecution(tool="naabu", stdout=out), "example.com")
    ports = {a.value for a in res.assets if a.type == AssetType.PORT}
    assert ports == {"example.com:80", "example.com:443"}
    assert res.relations and all(r.type == RelationType.EXPOSES for r in res.relations)


def test_nmap_grepable_parses_services():
    out = (
        "Host: 93.184.216.34 (example.com)\t"
        "Ports: 22/open/tcp//ssh//OpenSSH 8.9p1/, 443/open/tcp//https//nginx/\n"
    )
    res = NmapTool().parse(ToolExecution(tool="nmap", stdout=out), "example.com")
    services = [a for a in res.assets if a.type == AssetType.SERVICE]
    assert {s.attributes["port"] for s in services} == {22, 443}
    ssh = next(s for s in services if s.attributes["port"] == 22)
    assert ssh.attributes["service"] == "ssh"
    assert "OpenSSH" in ssh.attributes["product"]


def test_nuclei_parses_vulnerability_with_severity_and_affects():
    row = {
        "template-id": "tech-detect",
        "info": {"name": "Exposed Panel", "severity": "high"},
        "matched-at": "https://example.com/admin",
        "type": "http",
    }
    execution = ToolExecution(tool="nuclei", stdout=json.dumps(row) + "\n")
    res = NucleiTool().parse(execution, "example.com")
    vulns = [a for a in res.assets if a.type == AssetType.VULNERABILITY]
    assert vulns and vulns[0].attributes["severity"] == "high"
    assert vulns[0].attributes["name"] == "Exposed Panel"
    assert any(r.type == RelationType.AFFECTS for r in res.relations)


def test_nuclei_unknown_severity_falls_back_to_info():
    row = {"template-id": "x", "info": {"name": "y", "severity": "bogus"}, "matched-at": "h"}
    res = NucleiTool().parse(ToolExecution(tool="nuclei", stdout=json.dumps(row)), "example.com")
    assert res.assets[0].attributes["severity"] == "info"


def test_ffuf_parses_results_document():
    doc = {"results": [{"url": "https://example.com/admin", "status": 200, "length": 1234}]}
    res = FfufTool().parse(ToolExecution(tool="ffuf", stdout=json.dumps(doc)), "example.com")
    eps = [a for a in res.assets if a.type == AssetType.ENDPOINT]
    assert eps and eps[0].value.endswith("/admin")


def test_ffuf_skips_without_wordlist_builds_with_one():
    settings = Settings()
    assert FfufTool().build_command("example.com", settings) == []
    settings.active_recon.wordlist = "/tmp/words.txt"
    cmd = FfufTool().build_command("example.com", settings)
    assert "ffuf" in cmd and "/tmp/words.txt" in cmd and cmd[-1] != ""


def test_nuclei_command_includes_severity_and_rate_flags():
    settings = Settings()
    settings.active_recon.nuclei_severity = "high,critical"
    settings.active_recon.rate_limit = 50
    cmd = NucleiTool().build_command("https://example.com", settings)
    assert "-severity" in cmd and "high,critical" in cmd
    assert "-rate-limit" in cmd and "50" in cmd


def test_dirsearch_parses_status_and_path():
    out = "[12:00:00] 200 -    1KB - /admin/\n[12:00:01] 301 -    0B  - /login\n"
    res = DirsearchTool().parse(ToolExecution(tool="dirsearch", stdout=out), "example.com")
    paths = {a.value for a in res.assets}
    assert "https://example.com/admin/" in paths
    assert "https://example.com/login" in paths


# ---------------------------------------------------------------------------
# Framework — ToolExecution, runner, ExternalTool.run, plugin
# ---------------------------------------------------------------------------
def test_tool_execution_success_and_summary():
    assert ToolExecution(tool="x", exit_code=0).success is True
    assert ToolExecution(tool="x", timed_out=True).success is False
    assert ToolExecution(tool="x", skipped=True).success is False
    assert "timed out" in ToolExecution(tool="x", timed_out=True).summary()


def test_tool_execution_truncates_output():
    e = ToolExecution(tool="x", stdout="abcdef", stderr="123456")
    assert e.truncated(3).stdout == "abc"
    assert e.truncated(3).stderr == "123"
    assert e.truncated(0).stdout == "abcdef"  # 0 ⇒ no cap


def test_binary_available_false_for_missing():
    assert binary_available(_NONEXISTENT_BINARY) is False


class _MissingTool(ExternalTool):
    name = "missing"
    binary = _NONEXISTENT_BINARY

    def build_command(self, target, settings):  # noqa: ANN001
        return [self.binary, target]

    def parse(self, execution, target):  # noqa: ANN001
        return ReconResult(task_id="", module=self.name)


class _FakeRunner:
    """Stand-in ToolRunner returning a canned execution (no subprocess)."""

    def __init__(self, execution: ToolExecution) -> None:
        self._execution = execution

    async def run(self, command, *, timeout=None, retries=0, stdin=None):  # noqa: ANN001
        return self._execution


class _EchoTool(ExternalTool):
    name = "echo"
    binary = "echo"

    def available(self) -> bool:
        return True  # pretend the binary is on PATH

    def build_command(self, target, settings):  # noqa: ANN001
        return ["echo", target]

    def parse(self, execution, target):  # noqa: ANN001
        res = ReconResult(task_id="", module=self.name)
        url = execution.stdout.strip()
        res.assets.append(Asset(type=AssetType.URL, value=url, source=self.name))
        return res


async def test_run_skips_cleanly_when_binary_missing():
    ctx = ActiveToolContext("example.com", ToolRunner(), Settings())
    result, execution = await _MissingTool().run(ctx)
    assert execution.skipped is True
    assert result.assets == []
    assert any("not installed" in n for n in result.notes)


async def test_run_parses_output_via_fake_runner():
    runner = _FakeRunner(ToolExecution(tool="echo", stdout="https://example.com", exit_code=0))
    ctx = ActiveToolContext("example.com", runner, Settings())
    result, execution = await _EchoTool().run(ctx)
    assert execution.exit_code == 0
    assert any(a.value == "https://example.com" for a in result.assets)


def test_default_tool_set_is_complete():
    names = {t.name for t in build_active_tools()}
    expected = {
        "httpx", "subfinder", "amass", "naabu", "nmap",
        "katana", "gau", "dirsearch", "ffuf", "nuclei",
    }
    assert names == expected
    assert set(ACTIVE_TOOLS) == expected


def test_plugin_exposes_external_tools():
    factory = lambda: ActiveToolContext("example.com", ToolRunner(), Settings())  # noqa: E731
    plugin = ActiveReconPlugin(build_active_tools(), factory)
    tools = plugin.tools()
    names = {t.name for t in tools}
    assert "active.httpx" in names and "active.nuclei" in names
    for t in tools:
        assert ToolPermission.NETWORK_ACTIVE in t.permissions


async def test_plugin_tool_run_returns_result_shape():
    factory = lambda: ActiveToolContext("example.com", ToolRunner(), Settings())  # noqa: E731
    out = await ExternalToolTool(_MissingTool(), factory).run(target="example.com")
    assert set(out) >= {"assets", "relations", "notes", "execution"}
    assert out["execution"]["skipped"] is True


# ---------------------------------------------------------------------------
# Pipeline — two-key gate + stubbed end-to-end run
# ---------------------------------------------------------------------------
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


class _StubActiveTool(ExternalTool):
    """Active tool whose run yields a service + a vulnerability (no binary)."""

    name = "stub_active"
    binary = "stub_active"

    def build_command(self, target, settings):  # noqa: ANN001
        return ["stub_active", target]

    def parse(self, execution, target):  # noqa: ANN001
        return ReconResult(task_id="", module=self.name)

    async def run(self, ctx):  # noqa: ANN001
        result = ReconResult(task_id="", module=self.name)
        result.assets.append(
            Asset(
                type=AssetType.SERVICE,
                value="example.com:443",
                source="nmap",
                attributes={"via": "nmap", "service": "https", "host": "example.com", "port": 443},
            )
        )
        result.assets.append(
            Asset(
                type=AssetType.VULNERABILITY,
                value="exposed-panel@example.com",
                source="nuclei",
                attributes={
                    "via": "nuclei",
                    "name": "Exposed Admin Panel",
                    "severity": "high",
                    "matched_at": "https://example.com/admin",
                    "template": "exposed-panels",
                },
            )
        )
        return result, ToolExecution(tool=self.name, exit_code=0, stdout="ok")


@pytest.fixture(autouse=True)
def _patch_recon_modules(monkeypatch):
    factory = lambda: [_StubReconModule()]  # noqa: E731
    monkeypatch.setattr("recon_platform.agents.recon.build_passive_modules", factory)
    monkeypatch.setattr("recon_platform.agents.planner.build_passive_modules", factory)


def _base_settings() -> Settings:
    settings = Settings(authorized_only=False)
    settings.llm.enabled = False
    return settings


async def test_active_disabled_by_default_is_noop():
    settings = _base_settings()
    assert settings.active_recon.enabled is False
    orch = ReconOrchestrator(build_container(settings))

    bundle = await orch.run(EngagementContext(target="example.com"))

    assert not any(a.type == AssetType.VULNERABILITY for a in bundle.assets)
    # Disabled ⇒ the step returns before the agent runs, so no active trace at all.
    assert not any(t.agent == AgentRole.ACTIVE_RECON for t in bundle.traces)
    assert bundle.plan is not None and len(bundle.plan.tasks) == 3


async def test_active_enabled_but_unauthorized_skips():
    settings = _base_settings()
    settings.active_recon.enabled = True
    settings.active_recon.authorized = False  # second key withheld
    orch = ReconOrchestrator(build_container(settings))

    bundle = await orch.run(EngagementContext(target="example.com"))

    skips = [
        t for t in bundle.traces
        if t.agent == AgentRole.ACTIVE_RECON and t.action == "skip"
    ]
    assert skips and "not authorized" in skips[0].observation
    assert not any(a.type == AssetType.SERVICE for a in bundle.assets)


async def test_active_authorized_but_target_gate_fails_skips():
    # The engagement gate is exercised on the agent directly: with authorized_only
    # on and the target off-allowlist, the *passive* recon step would abort the
    # whole run first, so the active agent's own gate is tested in isolation here.
    from recon_platform.domain.interfaces import (
        KnowledgeGraph,
        LLMProvider,
        Memory,
        MessageBus,
    )

    settings = Settings(authorized_only=True, authorized_targets=["allowed.example"])
    settings.llm.enabled = False
    settings.active_recon.enabled = True
    settings.active_recon.authorized = True  # both keys present…
    container = build_container(settings)
    agent = ActiveReconAgent(
        container.resolve(MessageBus),  # type: ignore[type-abstract]
        container.resolve(Memory),  # type: ignore[type-abstract]
        container.resolve(LLMProvider),  # type: ignore[type-abstract]
        graph := container.resolve(KnowledgeGraph),  # type: ignore[type-abstract]
        settings,
    )

    # …but the target is not on the allowlist, so the engagement gate blocks it.
    assets, relations = await agent.run_active(EngagementContext(target="example.com"))

    assert assets == [] and relations == []
    assert not graph.assets(AssetType.SERVICE)


async def test_active_two_keys_runs_and_reports(monkeypatch):
    monkeypatch.setattr(
        "recon_platform.agents.active_recon.build_active_tools",
        lambda: [_StubActiveTool()],
    )
    settings = Settings(authorized_only=True, authorized_targets=["example.com"])
    settings.llm.enabled = False
    settings.active_recon.enabled = True
    settings.active_recon.authorized = True
    orch = ReconOrchestrator(build_container(settings))

    bundle = await orch.run(EngagementContext(target="example.com"))

    # Active assets reached the knowledge graph.
    assert any(a.type == AssetType.SERVICE for a in bundle.assets)
    assert any(a.type == AssetType.VULNERABILITY for a in bundle.assets)

    titles = [f.title.lower() for f in bundle.findings]
    assert any("exposed admin panel" in t for t in titles)
    assert any("active recon surface" in t for t in titles)

    from recon_platform.reporting.renderers import get_renderer

    md = get_renderer("markdown").render(bundle)
    assert "Active Reconnaissance" in md
    assert "example.com:443" in md

    # Plan is untouched (still the canonical 3-task passive plan).
    assert bundle.plan is not None and len(bundle.plan.tasks) == 3
