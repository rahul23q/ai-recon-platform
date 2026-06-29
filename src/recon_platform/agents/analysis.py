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
        findings += self._exposed_secrets_in_text()
        findings += self._sensitive_pages()
        findings += self._visual_capture()

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

    # -- vision rules (Phase 3) --------------------------------------------
    def _exposed_secrets_in_text(self) -> list[Finding]:
        """Secrets and sensitive information OCR'd from screenshots."""
        findings: list[Finding] = []

        secrets = [
            a
            for a in self.graph.assets(AssetType.SECRET)
            if a.attributes.get("from") == "ocr"
        ]
        if secrets:
            findings.append(
                Finding(
                    title="Secrets visible in screenshots",
                    description=(
                        f"{len(secrets)} high-signal secret(s) (API keys, tokens, or "
                        "private keys) were recognized by OCR in captured screenshots."
                    ),
                    severity=Severity.HIGH,
                    category="information-disclosure",
                    asset_keys=[s.key for s in secrets],
                    evidence=[
                        Evidence(
                            label=str(s.attributes.get("kind", "secret")),
                            detail=_mask(s.value),
                        )
                        for s in secrets[:20]
                    ],
                    recommendation=(
                        "Rotate the exposed credentials immediately and remove them "
                        "from any publicly rendered page."
                    ),
                    references={"cwe": "CWE-200", "owasp": "A02:2021-Cryptographic Failures"},
                    confidence=0.8,
                )
            )

        emails = [
            a for a in self.graph.assets(AssetType.EMAIL) if a.attributes.get("from") == "ocr"
        ]
        phones = [
            a
            for a in self.graph.assets(AssetType.TEXT_REGION)
            if a.attributes.get("kind") == "phone"
        ]
        internal = [
            a
            for a in self.graph.assets(AssetType.ENDPOINT)
            if a.attributes.get("internal")
        ]
        if emails or phones or internal:
            ev: list[Evidence] = []
            ev += [Evidence(label="email", detail=e.value) for e in emails[:15]]
            ev += [
                Evidence(label="phone", detail=str(p.attributes.get("text")))
                for p in phones[:15]
            ]
            ev += [Evidence(label="internal", detail=i.value) for i in internal[:15]]
            findings.append(
                Finding(
                    title="Sensitive information visible on screen",
                    description=(
                        "Personally identifiable information or internal references "
                        f"were observed visually: {len(emails)} email(s), "
                        f"{len(phones)} phone number(s), {len(internal)} internal URL(s)."
                    ),
                    severity=Severity.LOW,
                    category="information-disclosure",
                    asset_keys=[a.key for a in (emails + phones + internal)],
                    evidence=ev,
                    recommendation=(
                        "Avoid exposing PII and internal hostnames in public UI; "
                        "mask or remove where not required."
                    ),
                    references={"cwe": "CWE-200"},
                    confidence=0.7,
                )
            )
        return findings

    def _sensitive_pages(self) -> list[Finding]:
        """Login / admin / payment pages identified visually, plus missing-MFA."""
        screenshots = self.graph.assets(AssetType.SCREENSHOT)
        elements = self.graph.assets(AssetType.VISUAL_ELEMENT)
        if not screenshots and not elements:
            return []

        element_types = {str(e.attributes.get("element_type")) for e in elements}
        page_types = {str(s.attributes.get("page_type")) for s in screenshots}
        has_login = "login_portal" in page_types or "login_form" in element_types
        has_admin = "admin_panel" in page_types
        has_payment = "payment_page" in page_types
        has_mfa = "mfa" in element_types

        findings: list[Finding] = []
        if has_login or has_admin or has_payment:
            kinds = []
            if has_login:
                kinds.append("login portal")
            if has_admin:
                kinds.append("admin panel")
            if has_payment:
                kinds.append("payment page")
            findings.append(
                Finding(
                    title="Sensitive page(s) identified visually",
                    description=(
                        "Visual analysis identified sensitive interface(s): "
                        + ", ".join(kinds)
                        + ". These warrant access-control and authentication review."
                    ),
                    severity=Severity.MEDIUM if has_admin else Severity.LOW,
                    category="attack-surface",
                    asset_keys=[s.key for s in screenshots],
                    evidence=[
                        Evidence(
                            label=str(s.attributes.get("page_type")),
                            detail=str(s.value),
                            data={"screenshot": s.value},
                        )
                        for s in screenshots[:10]
                        if s.attributes.get("page_type") not in ("unknown", None)
                    ],
                    recommendation=(
                        "Confirm strong authentication and authorization on these pages."
                    ),
                    references={"owasp": "A01:2021-Broken Access Control"},
                    confidence=0.75,
                )
            )

        if has_login and not has_mfa:
            findings.append(
                Finding(
                    title="Login page without visible MFA",
                    description=(
                        "A login interface was detected but no multi-factor / one-time "
                        "code prompt was visible, suggesting single-factor authentication."
                    ),
                    severity=Severity.MEDIUM,
                    category="authentication",
                    asset_keys=[
                        s.key
                        for s in screenshots
                        if s.attributes.get("page_type") == "login_portal"
                    ],
                    evidence=[Evidence(label="signal", detail="no MFA element detected")],
                    recommendation="Enforce multi-factor authentication on user and admin logins.",
                    references={"owasp": "A07:2021-Identification and Authentication Failures"},
                    confidence=0.6,
                )
            )
        return findings

    def _visual_capture(self) -> list[Finding]:
        """Informational summary of vision-analyzed screenshots."""
        screenshots = self.graph.assets(AssetType.SCREENSHOT)
        if not screenshots:
            return []
        elements = self.graph.assets(AssetType.VISUAL_ELEMENT)
        evidence: list[Evidence] = []
        for s in screenshots[:20]:
            evidence.append(
                Evidence(
                    label=str(s.value),
                    detail=(
                        f"page={s.attributes.get('page_type', 'unknown')}, "
                        f"elements={s.attributes.get('elements', 0)}, "
                        f"ocr={s.attributes.get('ocr_provider', 'null')}"
                    ),
                    data={
                        "screenshot": s.value,
                        "annotated": s.attributes.get("annotated", ""),
                    },
                )
            )
        return [
            Finding(
                title=f"Visual analysis ({len(screenshots)} screenshot(s), "
                f"{len(elements)} element(s))",
                description=(
                    "The Vision agent ran OCR and element detection over captured "
                    "screenshots, classifying pages and extracting on-screen text."
                ),
                severity=Severity.INFO,
                category="recon",
                asset_keys=[s.key for s in screenshots],
                evidence=evidence,
                recommendation="Review screenshots and detected elements for exposed content.",
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


def _mask(value: str) -> str:
    """Mask a secret for evidence: keep a short prefix/suffix only."""
    v = value.strip()
    if len(v) <= 8:
        return "•" * len(v)
    return f"{v[:4]}…{v[-4:]} ({len(v)} chars)"
