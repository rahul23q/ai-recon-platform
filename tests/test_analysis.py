"""Analysis-agent rule tests (deterministic, no LLM, no network)."""

from __future__ import annotations

from recon_platform.a2a.bus import InMemoryMessageBus
from recon_platform.agents.analysis import AnalysisAgent
from recon_platform.domain.enums import AssetType, Severity
from recon_platform.domain.schemas import Asset
from recon_platform.knowledge_graph.graph import InMemoryKnowledgeGraph
from recon_platform.llm.provider import NullLLMProvider
from recon_platform.memory.store import InMemoryMemory


def _agent_with_assets(assets: list[Asset]) -> AnalysisAgent:
    graph = InMemoryKnowledgeGraph()
    for a in assets:
        graph.add_asset(a)
    return AnalysisAgent(InMemoryMessageBus(), InMemoryMemory(), NullLLMProvider(), graph)


async def test_missing_security_headers_finding():
    # Only a 'server' header present -> all recommended sec headers missing.
    assets = [
        Asset(
            type=AssetType.HEADER,
            value="server: nginx/1.25",
            attributes={"name": "server", "value": "nginx/1.25"},
        )
    ]
    agent = _agent_with_assets(assets)
    findings = await agent.analyze()
    titles = [f.title for f in findings]
    assert any("security headers" in t.lower() for t in titles)
    # version disclosure also fires (server header has a digit)
    assert any("disclosure" in t.lower() for t in titles)
    # severity ordering: highest first
    assert findings[0].severity.rank >= findings[-1].severity.rank


async def test_subdomain_surface_scales_severity():
    subs = [
        Asset(type=AssetType.SUBDOMAIN, value=f"h{i}.example.com") for i in range(25)
    ]
    agent = _agent_with_assets(subs)
    findings = await agent.analyze()
    sub_finding = next(f for f in findings if "Subdomain" in f.title)
    assert sub_finding.severity == Severity.LOW  # >20 subdomains


async def test_no_assets_yields_no_findings():
    agent = _agent_with_assets([])
    assert await agent.analyze() == []
