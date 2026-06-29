"""Cross-source verification tests (Phase 3.1) — hermetic.

Covers the false-positive class the verification pipeline is designed to remove:

* header case-insensitivity,
* analysis only on the final response after redirects,
* passive/browser agreement (Verified) and disagreement (Needs Verification /
  False Positive),
* false-positive detection (passive "missing" refuted by the browser).
"""

from __future__ import annotations

import httpx

from recon_platform.a2a.bus import InMemoryMessageBus
from recon_platform.agents.analysis import AnalysisAgent
from recon_platform.agents.verification import VerificationAgent
from recon_platform.core.config import Settings
from recon_platform.domain.enums import AssetType, VerificationStatus
from recon_platform.domain.schemas import Asset, EngagementContext
from recon_platform.knowledge_graph.graph import InMemoryKnowledgeGraph
from recon_platform.llm.provider import NullLLMProvider
from recon_platform.memory.store import InMemoryMemory
from recon_platform.recon.base import ModuleContext
from recon_platform.recon.modules import SECURITY_HEADERS, HTTPHeadersModule
from recon_platform.reporting.renderers import get_renderer
from recon_platform.verification.headers import (
    collect_header_maps,
    compute_header_verifications,
)

CSP = "content-security-policy"


def _hdr(name: str, value: str, source: str) -> Asset:
    """A HEADER asset as a module would emit it (attributes carry name/value)."""
    return Asset(
        type=AssetType.HEADER,
        value=f"{name.lower()}: {value}",
        source=source,
        attributes={"name": name.lower(), "value": value, "present": True},
    )


def _all_present_except(missing: set[str], source: str) -> list[Asset]:
    return [
        _hdr(h, "x", source) for h in SECURITY_HEADERS if h not in missing
    ]


# ---------------------------------------------------------------------------
# Pure verification logic
# ---------------------------------------------------------------------------
def test_header_comparison_is_case_insensitive():
    # Passive map provided with mixed-case key; CSP must count as present.
    passive = {"Content-Security-Policy": "default-src 'self'"}
    verdicts = {v.subject: v for v in compute_header_verifications(passive, {}, False)}
    csp = verdicts[f"security-header:{CSP}"]
    assert csp.claim == "present"


def test_agreement_missing_is_verified():
    verdicts = {
        v.subject: v for v in compute_header_verifications({}, {}, browser_observed=True)
    }
    csp = verdicts[f"security-header:{CSP}"]
    assert csp.status == VerificationStatus.VERIFIED
    assert csp.claim == "missing"


def test_agreement_present_is_verified():
    headers = {h: "x" for h in SECURITY_HEADERS}
    verdicts = {
        v.subject: v
        for v in compute_header_verifications(headers, headers, browser_observed=True)
    }
    csp = verdicts[f"security-header:{CSP}"]
    assert csp.status == VerificationStatus.VERIFIED
    assert csp.claim == "present"


def test_browser_passive_disagreement_present_needs_verification():
    # Passive saw it, browser didn't → present claim is unconfirmed.
    verdicts = {
        v.subject: v
        for v in compute_header_verifications({CSP: "x"}, {}, browser_observed=True)
    }
    csp = verdicts[f"security-header:{CSP}"]
    assert csp.status == VerificationStatus.NEEDS_VERIFICATION


def test_false_positive_detection_missing_in_passive_present_in_browser():
    # The reported-by-user case: passive says CSP missing, browser observed it.
    verdicts = {
        v.subject: v
        for v in compute_header_verifications({}, {CSP: "default-src 'self'"}, True)
    }
    csp = verdicts[f"security-header:{CSP}"]
    assert csp.status == VerificationStatus.FALSE_POSITIVE
    assert csp.claim == "missing"


def test_single_source_is_likely_when_no_browser():
    verdicts = {
        v.subject: v for v in compute_header_verifications({}, {}, browser_observed=False)
    }
    assert verdicts[f"security-header:{CSP}"].status == VerificationStatus.LIKELY


def test_collect_header_maps_splits_by_source_and_lowercases():
    graph = InMemoryKnowledgeGraph()
    graph.add_asset(_hdr("Content-Security-Policy", "p", "http_headers"))
    graph.add_asset(_hdr("X-Frame-Options", "DENY", "network_capture"))
    passive, browser, observed = collect_header_maps(graph)
    assert CSP in passive
    assert "x-frame-options" in browser
    assert observed is True


# ---------------------------------------------------------------------------
# Final response only (redirect chain) — via a mocked transport
# ---------------------------------------------------------------------------
async def test_header_analysis_uses_final_response_after_redirect():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(301, headers={"Location": "https://example.com/home"})
        # Final 200 carries a mixed-case CSP header.
        return httpx.Response(
            200,
            headers={"Content-Security-Policy": "default-src 'self'", "Content-Type": "text/html"},
            text="<html></html>",
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        ctx = ModuleContext("example.com", client, Settings(authorized_only=False))
        result = await HTTPHeadersModule().run(ctx)

    url_assets = [a for a in result.assets if a.type == AssetType.URL]
    assert url_assets and url_assets[0].attributes["status_code"] == 200
    assert url_assets[0].attributes["final"] is True
    assert url_assets[0].attributes["redirect_chain"]  # the 301 was recorded
    header_names = {
        a.attributes["name"] for a in result.assets if a.type == AssetType.HEADER
    }
    assert CSP in header_names  # case-normalized from the final response


# ---------------------------------------------------------------------------
# End-to-end via the agents (no orchestrator)
# ---------------------------------------------------------------------------
def _agent_pair(assets: list[Asset]):
    graph = InMemoryKnowledgeGraph()
    for a in assets:
        graph.add_asset(a)
    bus, mem, llm = InMemoryMessageBus(), InMemoryMemory(), NullLLMProvider()
    settings = Settings(authorized_only=False)
    verifier = VerificationAgent(bus, mem, llm, graph, settings)
    analyst = AnalysisAgent(bus, mem, llm, graph)
    return verifier, analyst


async def test_false_positive_not_reported_as_confirmed_missing():
    # Passive misses CSP; browser observed it. The pipeline must NOT confirm it
    # missing — it must surface a False Positive instead.
    assets = _all_present_except({CSP}, "http_headers")  # passive: all but CSP
    assets += [_hdr(h, "x", "network_capture") for h in SECURITY_HEADERS]  # browser: all
    verifier, analyst = _agent_pair(assets)

    verifications = await verifier.verify(EngagementContext(target="example.com"))
    findings = await analyst.analyze(verifications)

    fps = [f for f in findings if f.verification_status == VerificationStatus.FALSE_POSITIVE]
    assert fps, "expected a false-positive finding"
    assert any(CSP in e.label or CSP in e.detail for f in fps for e in f.evidence)

    # No confirmed-missing finding should claim CSP is missing.
    confirmed = [
        f
        for f in findings
        if f.verification_status in (VerificationStatus.VERIFIED, VerificationStatus.LIKELY)
        and "missing" in f.title.lower()
    ]
    assert all(CSP not in f.description for f in confirmed)


async def test_agreement_missing_reported_as_verified():
    # Neither passive nor browser has CSP → verified missing.
    assets = _all_present_except({CSP}, "http_headers")
    assets += _all_present_except({CSP}, "network_capture")
    verifier, analyst = _agent_pair(assets)

    verifications = await verifier.verify(EngagementContext(target="example.com"))
    findings = await analyst.analyze(verifications)

    verified_missing = [
        f
        for f in findings
        if f.verification_status == VerificationStatus.VERIFIED and "missing" in f.title.lower()
    ]
    assert verified_missing
    assert any(CSP in f.description for f in verified_missing)


async def test_report_has_verification_sections():
    from recon_platform.domain.schemas import Plan, ReportBundle

    assets = _all_present_except({CSP}, "http_headers")
    assets += [_hdr(h, "x", "network_capture") for h in SECURITY_HEADERS]
    verifier, analyst = _agent_pair(assets)
    verifications = await verifier.verify(EngagementContext(target="example.com"))
    findings = await analyst.analyze(verifications)

    bundle = ReportBundle(
        engagement=EngagementContext(target="example.com"),
        plan=Plan(engagement_id="e", objective="o"),
        findings=findings,
    )
    md = get_renderer("markdown").render(bundle)
    for title in (
        "Verified Findings",
        "Likely Findings",
        "Needs Manual Verification",
        "False Positives",
    ):
        assert title in md
