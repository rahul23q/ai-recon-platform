"""Domain schema + authorization + knowledge-graph unit tests."""

from __future__ import annotations

import pytest

from recon_platform.core.config import Settings
from recon_platform.core.exceptions import UnauthorizedTargetError
from recon_platform.domain.enums import AssetType, RelationType, Severity
from recon_platform.domain.schemas import Asset, EngagementContext, Finding, Relation, ReportBundle
from recon_platform.knowledge_graph.graph import InMemoryKnowledgeGraph
from recon_platform.recon.authorization import ensure_authorized, normalize_target


def test_severity_rank_orders_correctly():
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.INFO.rank


def test_asset_key_is_stable_and_lowercased():
    a = Asset(type=AssetType.DOMAIN, value="Example.COM")
    assert a.key == "domain:example.com"


def test_normalize_target_strips_scheme_and_path():
    assert normalize_target("https://Example.com:443/path") == "example.com"


def test_authorization_blocks_targets_outside_allowlist():
    settings = Settings(authorized_only=True, authorized_targets=["example.com"])
    assert ensure_authorized("sub.example.com", settings) == "sub.example.com"
    with pytest.raises(UnauthorizedTargetError):
        ensure_authorized("evil.test", settings)


def test_authorization_allows_any_when_no_allowlist():
    settings = Settings(authorized_only=True, authorized_targets=[])
    assert ensure_authorized("anything.test", settings) == "anything.test"


def test_knowledge_graph_dedups_and_links():
    g = InMemoryKnowledgeGraph()
    dom = Asset(type=AssetType.DOMAIN, value="example.com", confidence=0.5)
    g.add_asset(dom)
    # higher-confidence duplicate replaces, attributes merge
    g.add_asset(Asset(type=AssetType.DOMAIN, value="example.com", confidence=0.9,
                      attributes={"note": "x"}))
    assert len(g.assets(AssetType.DOMAIN)) == 1
    assert g.assets(AssetType.DOMAIN)[0].confidence == 0.9

    ip = Asset(type=AssetType.IP, value="93.184.216.34")
    g.add_asset(ip)
    g.add_relation(Relation(source_key=dom.key, target_key=ip.key,
                            type=RelationType.RESOLVES_TO))
    neighbors = g.neighbors(dom.key)
    assert ip.key in {n.key for n in neighbors}


def test_report_bundle_severity_counts():
    bundle = ReportBundle(
        engagement=EngagementContext(target="example.com"),
        findings=[
            Finding(title="a", severity=Severity.HIGH),
            Finding(title="b", severity=Severity.HIGH),
            Finding(title="c", severity=Severity.LOW),
        ],
    )
    counts = bundle.severity_counts
    assert counts["high"] == 2
    assert counts["low"] == 1
