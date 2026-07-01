"""Analysis agent — correlates assets into findings and ranks severity.

Deterministic rules produce a solid baseline (missing security headers,
technology/version disclosure, exposed paths, subdomain sprawl). When Claude is
available it adds an executive narrative; without it a templated summary is used.
"""

from __future__ import annotations

from recon_platform.agents.base import BaseAgent
from recon_platform.domain.enums import AgentRole, AssetType, Severity, VerificationStatus
from recon_platform.domain.interfaces import KnowledgeGraph, LLMProvider, Memory, MessageBus
from recon_platform.domain.schemas import Evidence, Finding, ReasoningTrace, Verification
from recon_platform.verification.headers import (
    SOURCE_BROWSER,
    SOURCE_PASSIVE,
    collect_header_maps,
    compute_header_verifications,
)

_SYSTEM = (
    "You are a senior security analyst summarizing PASSIVE recon results for an "
    "authorized engagement. Be precise and non-alarmist. Output an executive "
    "summary paragraph only."
)

#: Observer tag for vision-derived findings (passive/browser tags live in
#: ``verification.headers``).
SOURCE_VISION = "vision"
#: Observer tag for desktop-derived findings.
SOURCE_DESKTOP = "desktop"
#: Observer tag for active-recon (external tool) findings.
SOURCE_ACTIVE = "active-recon"
#: Observer tag for network-analysis (request/response correlation) findings.
SOURCE_NETWORK = "network"
#: Observer tag for API-discovery findings.
SOURCE_API = "api-discovery"
#: Observer tag for JavaScript-analysis findings.
SOURCE_JS = "js-analysis"


class AnalysisAgent(BaseAgent):
    def __init__(
        self, bus: MessageBus, memory: Memory, llm: LLMProvider, graph: KnowledgeGraph
    ) -> None:
        super().__init__(AgentRole.ANALYSIS, bus, memory, llm)
        self.graph = graph

    async def analyze(self, verifications: list[Verification] | None = None) -> list[Finding]:
        # When the Verification stage didn't run (e.g. AnalysisAgent used
        # directly), derive single-source verdicts from the graph so the
        # security-header rule still behaves correctly.
        if verifications is None:
            passive, browser, observed = collect_header_maps(self.graph)
            verifications = compute_header_verifications(passive, browser, observed)

        findings: list[Finding] = []
        # The security-header rule stamps its own (cross-source) verdicts; the
        # other rules are stamped with their originating observer so every finding
        # declares verification sources.
        findings += self._missing_security_headers(verifications)
        findings += _stamp(self._tech_disclosure(), [SOURCE_PASSIVE])
        findings += _stamp(self._exposed_paths(), [SOURCE_PASSIVE])
        findings += _stamp(self._subdomain_surface(), [SOURCE_PASSIVE])
        findings += _stamp(self._insecure_cookies(), [SOURCE_BROWSER])
        findings += _stamp(self._browser_capture(), [SOURCE_BROWSER])
        findings += _stamp(self._exposed_secrets_in_text(), [SOURCE_VISION])
        findings += _stamp(self._sensitive_pages(), [SOURCE_VISION])
        findings += _stamp(self._visual_capture(), [SOURCE_VISION])
        findings += _stamp(self._desktop_automation(), [SOURCE_DESKTOP])
        findings += _stamp(self._active_recon_vulnerabilities(), [SOURCE_ACTIVE])
        findings += _stamp(self._active_recon_surface(), [SOURCE_ACTIVE])
        findings += _stamp(self._network_jwt_weaknesses(), [SOURCE_NETWORK])
        findings += _stamp(self._network_cors(), [SOURCE_NETWORK])
        findings += _stamp(self._network_traffic_surface(), [SOURCE_NETWORK])
        findings += _stamp(self._api_inventory(), [SOURCE_API])
        findings += _stamp(self._api_weak_auth(), [SOURCE_API])
        findings += _stamp(self._js_secrets(), [SOURCE_JS])
        findings += _stamp(self._js_source_maps(), [SOURCE_JS])
        findings += _stamp(self._js_surface(), [SOURCE_JS])

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
    def _missing_security_headers(self, verifications: list[Verification]) -> list[Finding]:
        """Security-header findings, bucketed by cross-source verification verdict.

        A header is reported missing only with a verdict attached. The class of
        false positive where passive HTTP misses a header the browser actually
        receives is split out as a ``FALSE_POSITIVE`` finding rather than a
        confirmed gap.
        """
        # Only consider header verdicts (subject prefix), keyed by header name.
        header_verdicts = {
            v.subject.split(":", 1)[1]: v
            for v in verifications
            if v.subject.startswith("security-header:")
        }
        if not header_verdicts:
            return []

        # No HTTP response was observed at all (no HEADER assets) ⇒ we have no
        # basis to claim any header missing. Stay silent rather than fabricate.
        header_assets = self.graph.assets(AssetType.HEADER)
        if not header_assets:
            return []
        asset_keys = [h.key for h in header_assets]
        _ref = {"owasp": "A05:2021-Security Misconfiguration"}
        _rec = (
            "Add the missing headers (HSTS, CSP, X-Frame-Options, "
            "X-Content-Type-Options, Referrer-Policy, Permissions-Policy)."
        )

        # Group "missing" claims by verification status.
        verified_missing = [
            h for h, v in header_verdicts.items()
            if v.claim == "missing" and v.status == VerificationStatus.VERIFIED
        ]
        likely_missing = [
            h for h, v in header_verdicts.items()
            if v.claim == "missing" and v.status == VerificationStatus.LIKELY
        ]
        false_positives = [
            h for h, v in header_verdicts.items()
            if v.claim == "missing" and v.status == VerificationStatus.FALSE_POSITIVE
        ]
        needs_verification = [
            h for h, v in header_verdicts.items()
            if v.status == VerificationStatus.NEEDS_VERIFICATION
        ]

        findings: list[Finding] = []
        if verified_missing:
            findings.append(
                Finding(
                    title="Missing recommended security headers (verified)",
                    description=(
                        "These recommended HTTP security headers were absent from "
                        "both the passive HTTP and the browser responses: "
                        + ", ".join(verified_missing) + "."
                    ),
                    severity=Severity.MEDIUM,
                    category="hardening",
                    asset_keys=asset_keys,
                    evidence=[Evidence(label="missing", detail=", ".join(verified_missing))],
                    recommendation=_rec,
                    references=_ref,
                    confidence=0.95,
                    verification_status=VerificationStatus.VERIFIED,
                    verification_sources=[SOURCE_PASSIVE, SOURCE_BROWSER],
                )
            )
        if likely_missing:
            findings.append(
                Finding(
                    title="Missing recommended security headers",
                    description=(
                        "The passive HTTP response is missing one or more recommended "
                        "HTTP security headers: " + ", ".join(likely_missing) + ". "
                        "Enable the Browser agent to cross-verify (some servers send "
                        "these only to real browsers)."
                    ),
                    severity=Severity.MEDIUM,
                    category="hardening",
                    asset_keys=asset_keys,
                    evidence=[Evidence(label="missing", detail=", ".join(likely_missing))],
                    recommendation=_rec,
                    references=_ref,
                    confidence=0.8,
                    verification_status=VerificationStatus.LIKELY,
                    verification_sources=[SOURCE_PASSIVE],
                )
            )
        if needs_verification:
            findings.append(
                Finding(
                    title="Security headers needing manual verification",
                    description=(
                        "Passive HTTP and the browser disagreed about these headers; "
                        "manual confirmation is recommended: "
                        + ", ".join(sorted(needs_verification)) + "."
                    ),
                    severity=Severity.LOW,
                    category="hardening",
                    asset_keys=asset_keys,
                    evidence=[
                        Evidence(label=h, detail=header_verdicts[h].detail)
                        for h in sorted(needs_verification)
                    ],
                    recommendation="Manually confirm the header on the live target.",
                    references=_ref,
                    confidence=0.5,
                    verification_status=VerificationStatus.NEEDS_VERIFICATION,
                    verification_sources=[SOURCE_PASSIVE, SOURCE_BROWSER],
                )
            )
        if false_positives:
            findings.append(
                Finding(
                    title="Security header false positives (present in browser)",
                    description=(
                        "These headers were absent from the passive HTTP response but "
                        "observed in the browser response, so a 'missing header' "
                        "finding would be a false positive: "
                        + ", ".join(false_positives) + "."
                    ),
                    severity=Severity.INFO,
                    category="hardening",
                    asset_keys=asset_keys,
                    evidence=[
                        Evidence(label=h, detail=header_verdicts[h].detail)
                        for h in false_positives
                    ],
                    recommendation=(
                        "No action required for these headers; they are present for "
                        "browser clients."
                    ),
                    references=_ref,
                    confidence=0.2,
                    verification_status=VerificationStatus.FALSE_POSITIVE,
                    verification_sources=[SOURCE_PASSIVE, SOURCE_BROWSER],
                )
            )
        return findings

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

    # -- desktop rules (Phase 4) -------------------------------------------
    def _desktop_automation(self) -> list[Finding]:
        """Informational summary of desktop observation + interaction.

        Surfaces what the Desktop agent observed (open windows) and did (mouse /
        keyboard / clipboard / file-dialog actions). Actions actually *performed*
        (real synthetic input) are flagged so the report distinguishes them from
        the safe-mode planned (dry-run) interactions.
        """
        windows = self.graph.assets(AssetType.WINDOW)
        actions = self.graph.assets(AssetType.DESKTOP_ACTION)
        if not windows and not actions:
            return []

        performed = [a for a in actions if str(a.attributes.get("performed")) == "True"]
        by_type: dict[str, int] = {}
        for a in actions:
            kind = str(a.attributes.get("action_type", "action"))
            by_type[kind] = by_type.get(kind, 0) + 1

        evidence: list[Evidence] = []
        for w in windows[:15]:
            evidence.append(
                Evidence(
                    label="window",
                    detail=str(w.value),
                    data={"active": w.attributes.get("active", False)},
                )
            )
        for a in actions[:15]:
            evidence.append(
                Evidence(
                    label=str(a.attributes.get("action_type", "action")),
                    detail=str(a.value),
                    data={"performed": a.attributes.get("performed", "")},
                )
            )

        summary = ", ".join(f"{k}: {v}" for k, v in sorted(by_type.items())) or "none"
        description = (
            f"The Desktop agent observed {len(windows)} window(s) and recorded "
            f"{len(actions)} interaction(s) ({summary}). "
            + (
                f"{len(performed)} action(s) sent real input."
                if performed
                else "All interactions were planned (dry-run); no real input was sent."
            )
        )
        return [
            Finding(
                title=(
                    f"Desktop automation ({len(windows)} window(s), "
                    f"{len(actions)} action(s))"
                ),
                description=description,
                severity=Severity.INFO,
                category="recon",
                asset_keys=[a.key for a in (windows + actions)],
                evidence=evidence,
                recommendation=(
                    "Review desktop interactions for authorization scope; keep "
                    "synthetic input disabled (allow_input=False) unless explicitly "
                    "required by the engagement."
                ),
                confidence=0.9,
            )
        ]

    # -- active-recon rules (Phase 5) --------------------------------------
    def _active_recon_vulnerabilities(self) -> list[Finding]:
        """Turn tool-reported vulnerabilities (e.g. nuclei) into ranked findings."""
        vulns = self.graph.assets(AssetType.VULNERABILITY)
        if not vulns:
            return []
        findings: list[Finding] = []
        for v in vulns[:100]:
            sev_name = str(v.attributes.get("severity", "info")).lower()
            try:
                severity = Severity(sev_name)
            except ValueError:
                severity = Severity.INFO
            matched = str(v.attributes.get("matched_at", ""))
            tool = str(v.attributes.get("via", "active-recon"))
            findings.append(
                Finding(
                    title=f"{str(v.attributes.get('name', v.value))} ({tool})",
                    description=(
                        f"{tool} reported a {sev_name}-severity issue"
                        + (f" at {matched}" if matched else "")
                        + ". Validate and remediate per the referenced template."
                    ),
                    severity=severity,
                    category="vulnerability",
                    asset_keys=[v.key],
                    evidence=[
                        Evidence(
                            label=str(v.attributes.get("template", "match")),
                            detail=matched or str(v.value),
                            data={"severity": sev_name},
                        )
                    ],
                    recommendation=(
                        "Confirm the finding, then patch or mitigate the affected "
                        "component; suppress false positives in the tool config."
                    ),
                    references={"tool": tool},
                    confidence=0.7,
                )
            )
        return findings

    def _active_recon_surface(self) -> list[Finding]:
        """Informational summary of the surface uncovered by the active tools."""
        services = [
            a
            for a in (self.graph.assets(AssetType.SERVICE) + self.graph.assets(AssetType.PORT))
            if str(a.attributes.get("via")) in {"naabu", "nmap"}
        ]
        live = [
            a for a in self.graph.assets(AssetType.URL) if a.attributes.get("via") == "httpx"
        ]
        endpoints = [
            a
            for a in self.graph.assets(AssetType.ENDPOINT)
            if str(a.attributes.get("via")) in {"katana", "gau", "dirsearch", "ffuf"}
        ]
        subs = [
            a
            for a in self.graph.assets(AssetType.SUBDOMAIN)
            if a.source in {"subfinder", "amass"}
        ]
        if not (services or live or endpoints or subs):
            return []
        evidence: list[Evidence] = []
        evidence += [Evidence(label="service", detail=s.value) for s in services[:20]]
        evidence += [Evidence(label="live", detail=u.value) for u in live[:20]]
        evidence += [Evidence(label="endpoint", detail=e.value) for e in endpoints[:20]]
        return [
            Finding(
                title=(
                    f"Active recon surface ({len(services)} service(s), "
                    f"{len(live)} live host(s), {len(endpoints)} endpoint(s), "
                    f"{len(subs)} subdomain(s))"
                ),
                description=(
                    "External active-recon tools enumerated the live attack surface "
                    "(open services, responsive hosts, discovered endpoints, and "
                    "subdomains). Review for unintended exposure."
                ),
                severity=Severity.INFO,
                category="attack-surface",
                asset_keys=[a.key for a in (services + live + endpoints + subs)],
                evidence=evidence,
                recommendation=(
                    "Confirm each exposed service/endpoint is intended and hardened; "
                    "decommission anything unexpected."
                ),
                confidence=0.85,
            )
        ]

    # -- network rules (Phase 6) -------------------------------------------
    def _network_jwt_weaknesses(self) -> list[Finding]:
        """Flag decoded JWTs whose inspection surfaced weaknesses."""
        jwts = self.graph.assets(AssetType.JWT)
        weak = [j for j in jwts if j.attributes.get("issues")]
        if not weak:
            return []
        # Rank severity by the worst issue seen: alg=none / expiry absence is the
        # sharpest, sensitive-claim exposure the mildest.
        severity = Severity.LOW
        for j in weak:
            issues = " ".join(str(i).lower() for i in j.attributes.get("issues", []))
            if "alg=none" in issues:
                severity = Severity.HIGH
                break
            if "never expires" in issues or "symmetric alg" in issues:
                severity = Severity.MEDIUM
        evidence = [
            Evidence(
                label=str(j.attributes.get("alg") or "jwt"),
                detail="; ".join(str(i) for i in j.attributes.get("issues", [])),
                data={"source": str(j.attributes.get("source_kind", ""))},
            )
            for j in weak[:20]
        ]
        return [
            Finding(
                title=f"Weak JSON Web Token(s) detected ({len(weak)})",
                description=(
                    f"{len(weak)} JWT(s) observed in traffic carry weaknesses "
                    "(unsigned/symmetric algorithms, missing or past expiry, or "
                    "sensitive claims). Tokens were decoded for inspection only; "
                    "signatures were not verified."
                ),
                severity=severity,
                category="authentication",
                asset_keys=[j.key for j in weak],
                evidence=evidence,
                recommendation=(
                    "Reject alg=none and enforce a strong asymmetric algorithm; set "
                    "short-lived 'exp'; avoid placing sensitive data in token claims."
                ),
                references={
                    "cwe": "CWE-347",
                    "owasp": "A02:2021-Cryptographic Failures",
                },
                confidence=0.75,
            )
        ]

    def _network_cors(self) -> list[Finding]:
        """Dangerous CORS response-header configurations flagged by the agent."""
        headers = [
            h for h in self.graph.assets(AssetType.HEADER) if h.attributes.get("cors_issues")
        ]
        if not headers:
            return []
        all_issues: list[str] = []
        for h in headers:
            all_issues += [str(i) for i in h.attributes.get("cors_issues", [])]
        # Credentialed wildcard is the exploitable case; grade it higher.
        severity = (
            Severity.HIGH
            if any("with credentials" in i for i in all_issues)
            else Severity.MEDIUM
        )
        return [
            Finding(
                title="Insecure CORS configuration",
                description=(
                    "The Access-Control-Allow-Origin policy is overly permissive: "
                    + "; ".join(sorted(set(all_issues)))
                    + "."
                ),
                severity=severity,
                category="hardening",
                asset_keys=[h.key for h in headers],
                evidence=[
                    Evidence(label=str(h.attributes.get("value", h.value)), detail=i)
                    for h in headers
                    for i in h.attributes.get("cors_issues", [])
                ][:20],
                recommendation=(
                    "Reflect only an explicit allow-list of trusted origins; never "
                    "combine a wildcard/null origin with Allow-Credentials: true."
                ),
                references={"owasp": "A05:2021-Security Misconfiguration", "cwe": "CWE-942"},
                confidence=0.8,
            )
        ]

    def _network_traffic_surface(self) -> list[Finding]:
        """Insecure WebSockets + an informational API/WebSocket traffic summary."""
        findings: list[Finding] = []

        websockets = self.graph.assets(AssetType.WEBSOCKET)
        insecure_ws = [w for w in websockets if not w.attributes.get("secure", False)]
        if insecure_ws:
            findings.append(
                Finding(
                    title=f"Unencrypted WebSocket endpoint(s) ({len(insecure_ws)})",
                    description=(
                        f"{len(insecure_ws)} WebSocket endpoint(s) use the plaintext "
                        "ws:// scheme, exposing messages to interception and tampering."
                    ),
                    severity=Severity.MEDIUM,
                    category="hardening",
                    asset_keys=[w.key for w in insecure_ws],
                    evidence=[Evidence(label="ws", detail=w.value) for w in insecure_ws[:20]],
                    recommendation="Serve WebSockets over TLS (wss://) only.",
                    references={"owasp": "A02:2021-Cryptographic Failures", "cwe": "CWE-319"},
                    confidence=0.85,
                )
            )

        api_endpoints = self.graph.assets(AssetType.API_ENDPOINT)
        graphql = [a for a in api_endpoints if a.attributes.get("api_type") == "graphql"]
        if graphql:
            findings.append(
                Finding(
                    title=f"GraphQL endpoint(s) exposed ({len(graphql)})",
                    description=(
                        f"{len(graphql)} GraphQL endpoint(s) were identified in traffic. "
                        "GraphQL services frequently permit schema introspection, "
                        "revealing the full API surface."
                    ),
                    severity=Severity.LOW,
                    category="attack-surface",
                    asset_keys=[a.key for a in graphql],
                    evidence=[Evidence(label="graphql", detail=a.value) for a in graphql[:20]],
                    recommendation=(
                        "Disable introspection in production and enforce query "
                        "depth/complexity limits and authentication."
                    ),
                    references={"owasp": "API9:2023-Improper Inventory Management"},
                    confidence=0.6,
                )
            )

        if api_endpoints or websockets:
            findings.append(
                Finding(
                    title=(
                        f"Network traffic surface ({len(api_endpoints)} API endpoint(s), "
                        f"{len(websockets)} WebSocket(s))"
                    ),
                    description=(
                        "The Network agent correlated captured request/response data, "
                        "classifying API traffic (GraphQL / REST) and WebSocket endpoints."
                    ),
                    severity=Severity.INFO,
                    category="recon",
                    asset_keys=[a.key for a in (api_endpoints + websockets)],
                    evidence=(
                        [
                            Evidence(
                                label=str(a.attributes.get("api_type", "api")),
                                detail=a.value,
                            )
                            for a in api_endpoints[:15]
                        ]
                        + [
                            Evidence(
                                label="wss" if w.attributes.get("secure") else "ws",
                                detail=w.value,
                            )
                            for w in websockets[:15]
                        ]
                    ),
                    recommendation="Review the discovered API/WebSocket surface for exposure.",
                    confidence=0.85,
                )
            )
        return findings

    # -- api-discovery rules (Phase 7) -------------------------------------
    def _api_inventory(self) -> list[Finding]:
        """Informational inventory of the APIs discovered across all styles."""
        apis = self.graph.assets(AssetType.API)
        params = self.graph.assets(AssetType.API_PARAMETER)
        schemes = self.graph.assets(AssetType.AUTH_SCHEME)
        if not apis:
            return []
        by_style: dict[str, int] = {}
        for a in apis:
            style = str(a.attributes.get("style", "rest"))
            by_style[style] = by_style.get(style, 0) + 1
        style_summary = ", ".join(f"{k}: {v}" for k, v in sorted(by_style.items()))
        scheme_names = sorted({s.value for s in schemes})
        evidence: list[Evidence] = []
        for a in apis[:25]:
            detail = str(a.attributes.get("style", "rest"))
            resources = a.attributes.get("resources") or []
            if resources:
                detail += " · resources: " + ", ".join(str(r) for r in resources[:8])
            evidence.append(Evidence(label=a.value, detail=detail))
        return [
            Finding(
                title=f"API surface discovered ({len(apis)} API(s), {style_summary})",
                description=(
                    f"{len(apis)} API(s) were characterized from captured traffic "
                    f"({style_summary}); {len(params)} request parameter(s) and "
                    f"{len(scheme_names)} auth scheme(s) "
                    + (f"({', '.join(scheme_names)}) " if scheme_names else "")
                    + "were inferred. Review for undocumented or unintended exposure."
                ),
                severity=Severity.INFO,
                category="attack-surface",
                asset_keys=[a.key for a in apis],
                evidence=evidence,
                recommendation=(
                    "Confirm each API is intended, documented, authenticated, and "
                    "rate-limited; retire shadow/undocumented endpoints."
                ),
                references={"owasp": "API9:2023-Improper Inventory Management"},
                confidence=0.8,
            )
        ]

    def _api_weak_auth(self) -> list[Finding]:
        """Flag APIs discovered with no auth scheme, or with weak Basic auth."""
        apis = self.graph.assets(AssetType.API)
        if not apis:
            return []
        schemes = {s.value for s in self.graph.assets(AssetType.AUTH_SCHEME)}
        findings: list[Finding] = []

        # No authentication scheme observed alongside a discovered API surface.
        if not schemes:
            findings.append(
                Finding(
                    title="API surface without an observed authentication scheme",
                    description=(
                        f"{len(apis)} API(s) were discovered but no authentication "
                        "scheme (Bearer, API-key, cookie, …) was observed in the "
                        "captured headers, suggesting unauthenticated access or "
                        "auth applied inconsistently."
                    ),
                    severity=Severity.MEDIUM,
                    category="authentication",
                    asset_keys=[a.key for a in apis],
                    evidence=[Evidence(label=a.value, detail=str(a.attributes.get("style")))
                              for a in apis[:20]],
                    recommendation=(
                        "Require authentication on all API endpoints and verify it is "
                        "enforced server-side, not just in the client."
                    ),
                    references={"owasp": "API2:2023-Broken Authentication"},
                    confidence=0.55,
                )
            )

        if "basic" in schemes:
            findings.append(
                Finding(
                    title="HTTP Basic authentication in use",
                    description=(
                        "HTTP Basic authentication was observed. It transmits "
                        "base64-encoded (not encrypted) credentials on every request "
                        "and offers no protection beyond the transport layer."
                    ),
                    severity=Severity.MEDIUM,
                    category="authentication",
                    asset_keys=[
                        s.key
                        for s in self.graph.assets(AssetType.AUTH_SCHEME)
                        if s.value == "basic"
                    ],
                    evidence=[Evidence(label="scheme", detail="HTTP Basic")],
                    recommendation=(
                        "Prefer token-based auth (OAuth 2 / OIDC) over Basic; if Basic "
                        "is unavoidable, enforce HTTPS and short-lived credentials."
                    ),
                    references={"cwe": "CWE-522", "owasp": "API2:2023-Broken Authentication"},
                    confidence=0.6,
                )
            )
        return findings

    # -- js-analysis rules (Phase 8) ---------------------------------------
    def _js_secrets(self) -> list[Finding]:
        """Secrets embedded in JavaScript bundles (from=='js')."""
        secrets = [
            a
            for a in self.graph.assets(AssetType.SECRET)
            if a.attributes.get("via") == "js"
        ]
        if not secrets:
            return []
        return [
            Finding(
                title="Secrets embedded in JavaScript",
                description=(
                    f"{len(secrets)} high-signal secret(s) (API keys, tokens, or "
                    "private keys) were found in the client-side JavaScript, where "
                    "anyone can read them."
                ),
                severity=Severity.HIGH,
                category="information-disclosure",
                asset_keys=[s.key for s in secrets],
                evidence=[
                    Evidence(
                        label=str(s.attributes.get("kind", "secret")),
                        detail=_mask(s.value),
                        data={"js_file": s.attributes.get("js_file", "")},
                    )
                    for s in secrets[:20]
                ],
                recommendation=(
                    "Rotate the exposed credentials immediately and move secrets to "
                    "the server side; never ship them in client bundles."
                ),
                references={"cwe": "CWE-615", "owasp": "A02:2021-Cryptographic Failures"},
                confidence=0.8,
            )
        ]

    def _js_source_maps(self) -> list[Finding]:
        """Exposed source maps that reconstruct original client-side source."""
        maps = self.graph.assets(AssetType.SOURCE_MAP)
        if not maps:
            return []
        return [
            Finding(
                title=f"Source maps exposed ({len(maps)})",
                description=(
                    f"{len(maps)} JavaScript source map(s) were referenced. Source "
                    "maps reconstruct the original (pre-minification) source, "
                    "revealing internal structure, comments, and sometimes secrets."
                ),
                severity=Severity.LOW,
                category="information-disclosure",
                asset_keys=[m.key for m in maps],
                evidence=[Evidence(label="source map", detail=m.value) for m in maps[:20]],
                recommendation=(
                    "Do not deploy source maps to production, or restrict access to "
                    "them; strip sourceMappingURL comments from shipped bundles."
                ),
                references={"cwe": "CWE-540"},
                confidence=0.7,
            )
        ]

    def _js_surface(self) -> list[Finding]:
        """Informational summary of the client-side surface extracted from JS."""
        endpoints = [
            a
            for a in self.graph.assets(AssetType.ENDPOINT)
            if a.attributes.get("via") == "js"
        ]
        params = [
            a
            for a in self.graph.assets(AssetType.API_PARAMETER)
            if a.attributes.get("via") == "js"
        ]
        if not endpoints and not params:
            return []
        internal = [e for e in endpoints if e.attributes.get("internal")]
        return [
            Finding(
                title=(
                    f"Client-side surface from JavaScript "
                    f"({len(endpoints)} endpoint(s), {len(params)} parameter(s))"
                ),
                description=(
                    f"Analysis of the site's JavaScript extracted {len(endpoints)} "
                    f"endpoint(s) ({len(internal)} in-scope) and {len(params)} "
                    "request parameter(s), expanding the mapped attack surface for "
                    "the network and API-discovery agents."
                ),
                severity=Severity.INFO,
                category="attack-surface",
                asset_keys=[a.key for a in (endpoints + params)],
                evidence=[Evidence(label="endpoint", detail=e.value) for e in endpoints[:25]],
                recommendation=(
                    "Review JS-referenced endpoints for undocumented or sensitive "
                    "functionality and confirm each enforces authorization."
                ),
                confidence=0.8,
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


def _stamp(findings: list[Finding], sources: list[str]) -> list[Finding]:
    """Record the originating observer(s) on findings that didn't set their own."""
    for f in findings:
        if not f.verification_sources:
            f.verification_sources = list(sources)
    return findings
