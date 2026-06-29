"""Analysis agent — correlates assets into findings and ranks severity.

Deterministic rules produce a solid baseline (missing security headers,
technology/version disclosure, exposed paths, subdomain sprawl). When Claude is
available it adds an executive narrative; without it a templated summary is used.
"""

from __future__ import annotations

from recon_platform.agents.base import BaseAgent
from recon_platform.domain.enums import AgentRole, AssetType, Severity
from recon_platform.domain.interfaces import KnowledgeGraph, LLMProvider, Memory, MessageBus
from recon_platform.domain.schemas import Evidence, Finding, ReasoningTrace
from recon_platform.recon.modules import SECURITY_HEADERS

_SYSTEM = (
    "You are a senior security analyst summarizing PASSIVE recon results for an "
    "authorized engagement. Be precise and non-alarmist. Output an executive "
    "summary paragraph only."
)


class AnalysisAgent(BaseAgent):
    def __init__(
        self, bus: MessageBus, memory: Memory, llm: LLMProvider, graph: KnowledgeGraph
    ) -> None:
        super().__init__(AgentRole.ANALYSIS, bus, memory, llm)
        self.graph = graph

    async def analyze(self) -> list[Finding]:
        findings: list[Finding] = []
        findings += self._missing_security_headers()
        findings += self._tech_disclosure()
        findings += self._exposed_paths()
        findings += self._subdomain_surface()
        findings += self._insecure_cookies()
        findings += self._browser_capture()

        findings.sort(key=lambda f: f.severity.rank, reverse=True)

        await self.record(
            ReasoningTrace(
                agent=self.role,
                action="correlate",
                observation=f"{len(self.graph.assets())} assets analyzed",
                result=f"{len(findings)} findings",
                reflection="ranked by severity",
                confidence=0.8,
                next_action="report",
            )
        )
        await self.announce(
            recipient=AgentRole.REPORTING,
            reason=f"analysis complete: {len(findings)} findings",
            result={"findings": len(findings)},
            confidence=0.8,
        )
        return findings

    # -- rules --------------------------------------------------------------
    def _missing_security_headers(self) -> list[Finding]:
        headers = self.graph.assets(AssetType.HEADER)
        if not headers:
            return []
        present = {str(h.attributes.get("name", "")).lower() for h in headers}
        missing = [h for h in SECURITY_HEADERS if h not in present]
        if not missing:
            return []
        return [
            Finding(
                title="Missing recommended security headers",
                description=(
                    "The application response is missing one or more recommended "
                    "HTTP security headers: " + ", ".join(missing) + "."
                ),
                severity=Severity.MEDIUM,
                category="hardening",
                asset_keys=[h.key for h in headers],
                evidence=[Evidence(label="missing", detail=", ".join(missing))],
                recommendation=(
                    "Add the missing headers (HSTS, CSP, X-Frame-Options, "
                    "X-Content-Type-Options, Referrer-Policy, Permissions-Policy)."
                ),
                references={"owasp": "A05:2021-Security Misconfiguration"},
                confidence=0.9,
            )
        ]

    def _tech_disclosure(self) -> list[Finding]:
        techs = self.graph.assets(AssetType.TECHNOLOGY)
        # Version-bearing Server / X-Powered-By headers.
        verbose = [
            h
            for h in self.graph.assets(AssetType.HEADER)
            if h.attributes.get("name") in {"server", "x-powered-by"}
            and any(ch.isdigit() for ch in str(h.attributes.get("value", "")))
        ]
        if not techs and not verbose:
            return []
        ev = [Evidence(label=t.value, detail="technology fingerprint") for t in techs]
        ev += [
            Evidence(label=str(h.attributes.get("name")), detail=str(h.attributes.get("value")))
            for h in verbose
        ]
        return [
            Finding(
                title="Technology / version disclosure",
                description=(
                    "Server software and component versions are disclosed via "
                    "response headers or page markers, aiding targeted attacks."
                ),
                severity=Severity.LOW,
                category="information-disclosure",
                asset_keys=[t.key for t in techs] + [h.key for h in verbose],
                evidence=ev,
                recommendation="Suppress version banners in server/proxy config.",
                references={"cwe": "CWE-200"},
                confidence=0.7,
            )
        ]

    def _exposed_paths(self) -> list[Finding]:
        endpoints = [
            a
            for a in self.graph.assets(AssetType.ENDPOINT)
            if a.attributes.get("from") == "robots.txt"
        ]
        if not endpoints:
            return []
        return [
            Finding(
                title="Paths disclosed via robots.txt",
                description=(
                    f"robots.txt references {len(endpoints)} path(s) that reveal "
                    "application structure and potentially sensitive areas."
                ),
                severity=Severity.INFO,
                category="information-disclosure",
                asset_keys=[e.key for e in endpoints],
                evidence=[Evidence(label="path", detail=e.value) for e in endpoints[:20]],
                recommendation="Avoid listing sensitive paths in robots.txt.",
                confidence=0.8,
            )
        ]

    def _subdomain_surface(self) -> list[Finding]:
        subs = self.graph.assets(AssetType.SUBDOMAIN)
        if not subs:
            return []
        sev = Severity.LOW if len(subs) > 20 else Severity.INFO
        return [
            Finding(
                title=f"Subdomain attack surface ({len(subs)} discovered)",
                description=(
                    f"{len(subs)} subdomain(s) were enumerated from Certificate "
                    "Transparency, expanding the externally reachable surface."
                ),
                severity=sev,
                category="attack-surface",
                asset_keys=[s.key for s in subs],
                evidence=[Evidence(label="subdomain", detail=s.value) for s in subs[:30]],
                recommendation="Inventory subdomains; decommission unused hosts.",
                confidence=0.85,
            )
        ]

    def _insecure_cookies(self) -> list[Finding]:
        """COOKIE assets missing Secure / HttpOnly / SameSite (browser-observed)."""
        cookies = self.graph.assets(AssetType.COOKIE)
        if not cookies:
            return []
        weak = []
        for c in cookies:
            missing = [
                flag
                for flag, attr in (
                    ("Secure", "secure"),
                    ("HttpOnly", "http_only"),
                )
                if not c.attributes.get(attr, False)
            ]
            same_site = str(c.attributes.get("same_site", "")).lower()
            if same_site in ("", "none"):
                missing.append("SameSite")
            if missing:
                weak.append((c, missing))
        if not weak:
            return []
        return [
            Finding(
                title="Cookies missing security attributes",
                description=(
                    f"{len(weak)} cookie(s) observed in the browser are missing one "
                    "or more protective attributes (Secure, HttpOnly, SameSite), "
                    "increasing exposure to theft and cross-site attacks."
                ),
                severity=Severity.MEDIUM,
                category="hardening",
                asset_keys=[c.key for c, _ in weak],
                evidence=[
                    Evidence(label=c.value, detail="missing: " + ", ".join(missing))
                    for c, missing in weak[:20]
                ],
                recommendation=(
                    "Set Secure and HttpOnly on session cookies and an explicit "
                    "SameSite policy (Lax or Strict)."
                ),
                references={"owasp": "A05:2021-Security Misconfiguration", "cwe": "CWE-1004"},
                confidence=0.85,
            )
        ]

    def _browser_capture(self) -> list[Finding]:
        """Informational finding summarizing browser-navigated pages + screenshots."""
        pages = [
            a
            for a in self.graph.assets(AssetType.URL)
            if a.attributes.get("via") == "browser"
        ]
        if not pages:
            return []
        evidence: list[Evidence] = []
        for p in pages[:20]:
            detail = str(p.attributes.get("title") or p.value)
            shot = p.attributes.get("screenshot")
            evidence.append(
                Evidence(
                    label=p.value,
                    detail=detail,
                    data={"screenshot": shot} if shot else {},
                )
            )
        return [
            Finding(
                title=f"Browser capture ({len(pages)} page(s) navigated)",
                description=(
                    f"A real browser navigated {len(pages)} page(s), capturing the "
                    "rendered DOM, network traffic, cookies, and screenshot evidence."
                ),
                severity=Severity.INFO,
                category="recon",
                asset_keys=[p.key for p in pages],
                evidence=evidence,
                recommendation="Review captured pages and screenshots for exposed content.",
                confidence=0.9,
            )
        ]

    async def executive_summary(self, findings: list[Finding], target: str) -> str:
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        templated = (
            f"Passive reconnaissance of {target} surfaced {len(findings)} finding(s) "
            f"({counts}). No intrusive testing was performed."
        )
        if not self.llm.available:
            return templated
        prompt = (
            f"Target: {target}\nFindings:\n"
            + "\n".join(f"- [{f.severity.value}] {f.title}" for f in findings)
            + "\nWrite a 2-3 sentence executive summary."
        )
        try:
            return (await self.llm.complete(_SYSTEM, prompt)) or templated
        except Exception:  # noqa: BLE001
            return templated
