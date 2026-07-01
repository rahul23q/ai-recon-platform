"""Report renderers.

Each renderer implements the `ReportRenderer` Protocol (``format`` + ``render``)
and turns a `ReportBundle` into a concrete document. Phase 1 ships Markdown,
HTML, and JSON; PDF/DOCX renderers slot in behind the same Protocol later.
"""

from __future__ import annotations

import html

from recon_platform.core.exceptions import ConfigurationError
from recon_platform.domain.enums import AssetType, VerificationStatus
from recon_platform.domain.schemas import Finding, ReportBundle

_SECTION_ORDER = ["critical", "high", "medium", "low", "info"]

# Verification buckets, in report order, with their human section titles.
_VERIFICATION_SECTIONS: list[tuple[VerificationStatus, str]] = [
    (VerificationStatus.VERIFIED, "Verified Findings"),
    (VerificationStatus.LIKELY, "Likely Findings"),
    (VerificationStatus.NEEDS_VERIFICATION, "Needs Manual Verification"),
    (VerificationStatus.FALSE_POSITIVE, "False Positives"),
]


class JSONRenderer:
    format = "json"

    def render(self, bundle: ReportBundle) -> str:
        return bundle.model_dump_json(indent=2)


class MarkdownRenderer:
    format = "markdown"

    def render(self, bundle: ReportBundle) -> str:
        eng = bundle.engagement
        lines: list[str] = []
        lines.append(f"# Reconnaissance Report — {eng.target}")
        lines.append("")
        lines.append(f"*Engagement `{eng.id}` · generated {bundle.generated_at.isoformat()}*")
        lines.append("")
        lines.append("> Authorized passive reconnaissance. No intrusive testing performed.")
        lines.append("")

        # Executive summary
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(eng.notes or "Passive reconnaissance completed.")
        lines.append("")
        counts = bundle.severity_counts
        lines.append(
            "**Findings by severity:** "
            + ", ".join(f"{k}: {counts.get(k, 0)}" for k in _SECTION_ORDER)
        )
        lines.append("")

        # Methodology / plan
        if bundle.plan:
            lines.append("## Methodology")
            lines.append("")
            lines.append(f"**Objective:** {bundle.plan.objective}")
            lines.append("")
            lines.append(bundle.plan.rationale)
            lines.append("")
            for t in bundle.plan.tasks:
                lines.append(f"- **{t.title}** → `{t.assigned_role}` ({t.status})")
            lines.append("")

        # Findings — grouped by cross-source verification status.
        lines.append("## Findings")
        lines.append("")
        if not bundle.findings:
            lines.append("_No findings._")
            lines.append("")
        buckets: dict[str, list[Finding]] = {}
        for f in bundle.findings:
            status = f.verification_status
            key = status.value if hasattr(status, "value") else str(status)
            buckets.setdefault(key, []).append(f)
        for status, title in _VERIFICATION_SECTIONS:
            group = buckets.get(status.value, [])
            lines.append(f"### {title} ({len(group)})")
            lines.append("")
            if not group:
                lines.append("_None._")
                lines.append("")
                continue
            for f in sorted(group, key=lambda x: x.severity.rank, reverse=True):
                self._render_finding(lines, f)

        # Discovered assets
        lines.append("## Discovered Assets")
        lines.append("")
        by_type: dict[str, list[str]] = {}
        for a in bundle.assets:
            t = a.type.value if hasattr(a.type, "value") else str(a.type)
            by_type.setdefault(t, []).append(a.value)
        for t in sorted(by_type):
            vals = by_type[t]
            lines.append(f"### {t} ({len(vals)})")
            for v in sorted(set(vals))[:50]:
                lines.append(f"- `{v}`")
            lines.append("")

        # Visual intelligence (Phase 3) — only when screenshots were analyzed.
        screenshots = [a for a in bundle.assets if a.type == AssetType.SCREENSHOT]
        if screenshots:
            elements = [a for a in bundle.assets if a.type == AssetType.VISUAL_ELEMENT]
            lines.append("## Visual Intelligence")
            lines.append("")
            for s in screenshots[:20]:
                page = s.attributes.get("page_type", "unknown")
                conf = s.attributes.get("page_confidence", 0)
                ocr = s.attributes.get("ocr_provider", "null")
                n = s.attributes.get("elements", 0)
                lines.append(f"### `{s.value}`")
                lines.append("")
                lines.append(
                    f"- **Page type:** {page} (confidence {conf}) · "
                    f"**Elements:** {n} · **OCR:** {ocr}"
                )
                annotated = s.attributes.get("annotated")
                if annotated:
                    lines.append(f"- **Annotated:** `{annotated}`")
                lines.append("")
            if elements:
                by_kind: dict[str, int] = {}
                for e in elements:
                    kind = str(e.attributes.get("element_type", "element"))
                    by_kind[kind] = by_kind.get(kind, 0) + 1
                summary = ", ".join(f"{k}: {v}" for k, v in sorted(by_kind.items()))
                lines.append(f"**Detected elements:** {summary}")
                lines.append("")

        # Desktop automation (Phase 4) — only when the desktop agent ran.
        windows = [a for a in bundle.assets if a.type == AssetType.WINDOW]
        actions = [a for a in bundle.assets if a.type == AssetType.DESKTOP_ACTION]
        if windows or actions:
            lines.append("## Desktop Automation")
            lines.append("")
            if windows:
                lines.append(f"**Windows discovered ({len(windows)}):**")
                for w in windows[:30]:
                    active = " · active" if w.attributes.get("active") else ""
                    lines.append(f"- `{w.value}`{active}")
                lines.append("")
            if actions:
                by_kind: dict[str, int] = {}
                for a in actions:
                    kind = str(a.attributes.get("action_type", "action"))
                    by_kind[kind] = by_kind.get(kind, 0) + 1
                summary = ", ".join(f"{k}: {v}" for k, v in sorted(by_kind.items()))
                lines.append(f"**Interactions ({len(actions)}):** {summary}")
                lines.append("")
                for a in actions[:30]:
                    state = (
                        "performed"
                        if str(a.attributes.get("performed")) == "True"
                        else "planned (dry-run)"
                    )
                    lines.append(f"- [{state}] {a.value}")
                lines.append("")

        # Active reconnaissance (Phase 5) — only when active tools ran.
        services = [
            a for a in bundle.assets if a.type in (AssetType.SERVICE, AssetType.PORT)
        ]
        vulns = [a for a in bundle.assets if a.type == AssetType.VULNERABILITY]
        if services or vulns:
            lines.append("## Active Reconnaissance")
            lines.append("")
            if services:
                lines.append(f"**Open services / ports ({len(services)}):**")
                for s in services[:40]:
                    svc = s.attributes.get("service") or s.attributes.get("product") or ""
                    suffix = f" — {svc}" if svc else ""
                    lines.append(f"- `{s.value}`{suffix}")
                lines.append("")
            if vulns:
                by_sev: dict[str, int] = {}
                for v in vulns:
                    sev = str(v.attributes.get("severity", "info"))
                    by_sev[sev] = by_sev.get(sev, 0) + 1
                summary = ", ".join(f"{k}: {v}" for k, v in sorted(by_sev.items()))
                lines.append(f"**Reported vulnerabilities ({len(vulns)}):** {summary}")
                lines.append("")
                for v in vulns[:40]:
                    sev = str(v.attributes.get("severity", "info")).upper()
                    name = v.attributes.get("name", v.value)
                    matched = v.attributes.get("matched_at", "")
                    lines.append(f"- [{sev}] {name}" + (f" — `{matched}`" if matched else ""))
                lines.append("")

        # Network analysis (Phase 6) — only when the network agent produced assets.
        jwts = [a for a in bundle.assets if a.type == AssetType.JWT]
        api_endpoints = [a for a in bundle.assets if a.type == AssetType.API_ENDPOINT]
        websockets = [a for a in bundle.assets if a.type == AssetType.WEBSOCKET]
        cors = [a for a in bundle.assets if a.attributes.get("cors_issues")]
        if jwts or api_endpoints or websockets or cors:
            lines.append("## Network Analysis")
            lines.append("")
            if jwts:
                lines.append(f"**JSON Web Tokens ({len(jwts)}):**")
                for j in jwts[:30]:
                    alg = j.attributes.get("alg") or "?"
                    issues = j.attributes.get("issues") or []
                    suffix = f" — {'; '.join(str(i) for i in issues)}" if issues else " — ok"
                    lines.append(f"- `{j.value}` (alg={alg}){suffix}")
                lines.append("")
            if cors:
                lines.append(f"**CORS misconfigurations ({len(cors)}):**")
                for c in cors[:20]:
                    for i in c.attributes.get("cors_issues", []):
                        lines.append(f"- {i}")
                lines.append("")
            if api_endpoints:
                by_type: dict[str, int] = {}
                for a in api_endpoints:
                    t = str(a.attributes.get("api_type", "api"))
                    by_type[t] = by_type.get(t, 0) + 1
                summary = ", ".join(f"{k}: {v}" for k, v in sorted(by_type.items()))
                lines.append(f"**API traffic ({len(api_endpoints)}):** {summary}")
                for a in api_endpoints[:30]:
                    lines.append(f"- [{a.attributes.get('api_type', 'api')}] `{a.value}`")
                lines.append("")
            if websockets:
                insecure = sum(1 for w in websockets if not w.attributes.get("secure"))
                lines.append(
                    f"**WebSocket endpoints ({len(websockets)}, {insecure} insecure):**"
                )
                for w in websockets[:30]:
                    scheme = "wss" if w.attributes.get("secure") else "ws"
                    lines.append(f"- [{scheme}] `{w.value}`")
                lines.append("")

        # API discovery (Phase 7) — only when the API agent produced assets.
        apis = [a for a in bundle.assets if a.type == AssetType.API]
        parameters = [a for a in bundle.assets if a.type == AssetType.API_PARAMETER]
        auth_schemes = [a for a in bundle.assets if a.type == AssetType.AUTH_SCHEME]
        if apis or auth_schemes:
            lines.append("## API Discovery")
            lines.append("")
            if apis:
                by_style: dict[str, int] = {}
                for a in apis:
                    s = str(a.attributes.get("style", "rest"))
                    by_style[s] = by_style.get(s, 0) + 1
                summary = ", ".join(f"{k}: {v}" for k, v in sorted(by_style.items()))
                lines.append(f"**APIs discovered ({len(apis)}):** {summary}")
                for a in apis[:40]:
                    style = a.attributes.get("style", "rest")
                    version = a.attributes.get("version")
                    resources = a.attributes.get("resources") or []
                    extra = f" v{version}" if version else ""
                    if resources:
                        extra += " — " + ", ".join(str(r) for r in resources[:8])
                    lines.append(f"- [{style}] `{a.value}`{extra}")
                lines.append("")
            if auth_schemes:
                names = ", ".join(sorted({s.value for s in auth_schemes}))
                lines.append(f"**Authentication schemes ({len(auth_schemes)}):** {names}")
                lines.append("")
            if parameters:
                lines.append(f"**Request parameters ({len(parameters)}):**")
                for p in parameters[:40]:
                    loc = p.attributes.get("location", "query")
                    lines.append(f"- `{p.attributes.get('name', p.value)}` ({loc})")
                lines.append("")

        # JavaScript analysis (Phase 8) — only when the JS agent produced assets.
        js_endpoints = [
            a for a in bundle.assets
            if a.type == AssetType.ENDPOINT and a.attributes.get("via") == "js"
        ]
        js_secrets = [
            a for a in bundle.assets
            if a.type == AssetType.SECRET and a.attributes.get("via") == "js"
        ]
        source_maps = [a for a in bundle.assets if a.type == AssetType.SOURCE_MAP]
        if js_endpoints or js_secrets or source_maps:
            lines.append("## JavaScript Analysis")
            lines.append("")
            if js_endpoints:
                internal = sum(1 for e in js_endpoints if e.attributes.get("internal"))
                lines.append(
                    f"**Endpoints from JS ({len(js_endpoints)}, {internal} in-scope):**"
                )
                for e in js_endpoints[:40]:
                    lines.append(f"- `{e.value}`")
                lines.append("")
            if js_secrets:
                lines.append(f"**Secrets in JS ({len(js_secrets)}):**")
                for s in js_secrets[:20]:
                    kind = s.attributes.get("kind", "secret")
                    lines.append(f"- [{kind}] `{s.attributes.get('js_file', '')}`")
                lines.append("")
            if source_maps:
                lines.append(f"**Source maps ({len(source_maps)}):**")
                for m in source_maps[:20]:
                    lines.append(f"- `{m.value}`")
                lines.append("")

        # Authentication (Phase 9) — only when the auth agent produced sessions.
        sessions = [a for a in bundle.assets if a.type == AssetType.SESSION]
        if sessions:
            lines.append("## Authentication")
            lines.append("")
            lines.append(
                "> Credentials are never shown; only workflow outcomes and captured "
                "cookie names are reported (values stay in episodic memory)."
            )
            lines.append("")
            for s in sessions[:40]:
                wf = s.attributes.get("workflow", "?")
                outcome = "✓" if s.attributes.get("success") else "✗"
                url = s.attributes.get("url", "")
                reason = s.attributes.get("reason", "")
                lines.append(f"- [{outcome}] **{wf}** `{url}` — {reason}")
                names = s.attributes.get("cookie_names") or []
                if names:
                    lines.append(f"  - session cookies: {', '.join(names)}")
            lines.append("")

        # Appendix: reasoning trace
        lines.append("## Appendix — Reasoning Trace")
        lines.append("")
        for tr in bundle.traces:
            agent = tr.agent.value if hasattr(tr.agent, "value") else str(tr.agent)
            lines.append(
                f"- `{agent}` **{tr.action}** — {tr.result} "
                f"(confidence {tr.confidence:.2f})"
            )
        lines.append("")
        return "\n".join(lines)

    @staticmethod
    def _render_finding(lines: list[str], f: Finding) -> None:
        """Render one finding, including its verification status / confidence."""
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        status = f.verification_status
        status_str = status.value if hasattr(status, "value") else str(status)
        lines.append(f"#### [{sev.upper()}] {f.title}")
        lines.append("")
        sources = ", ".join(f.verification_sources) or "—"
        lines.append(
            f"*Verification: **{status_str.replace('_', ' ')}** · "
            f"confidence {f.confidence:.2f} · sources: {sources}*"
        )
        lines.append("")
        lines.append(f.description)
        lines.append("")
        if f.recommendation:
            lines.append(f"**Recommendation:** {f.recommendation}")
            lines.append("")
        if f.references:
            refs = ", ".join(f"{k}: {v}" for k, v in f.references.items())
            lines.append(f"**References:** {refs}")
            lines.append("")
        if f.evidence:
            lines.append("**Evidence:**")
            for e in f.evidence[:25]:
                lines.append(f"- {e.label}: {e.detail}")
            lines.append("")


class HTMLRenderer:
    format = "html"

    def render(self, bundle: ReportBundle) -> str:
        md = MarkdownRenderer().render(bundle)
        # Minimal, dependency-free HTML wrapper preserving the Markdown as text.
        body = html.escape(md)
        eng = bundle.engagement
        gallery = self._gallery(bundle)
        return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Recon Report — {html.escape(eng.target)}</title>
<style>
 body {{ font-family: ui-monospace, monospace; max-width: 60rem; margin: 2rem auto;
        line-height: 1.5; color: #1a1a1a; }}
 pre {{ white-space: pre-wrap; }}
 header {{ border-bottom: 2px solid #ddd; margin-bottom: 1rem; }}
 figure {{ margin: 1rem 0; }}
 figure img {{ max-width: 100%; border: 1px solid #ccc; }}
 figcaption {{ font-size: 0.85rem; color: #555; }}
</style>
</head>
<body>
<header><h1>Recon Report — {html.escape(eng.target)}</h1></header>
<pre>{body}</pre>
{gallery}
</body>
</html>"""

    def _gallery(self, bundle: ReportBundle) -> str:
        """Embed analyzed screenshots (annotated when available) for the report."""
        shots = [a for a in bundle.assets if a.type == AssetType.SCREENSHOT]
        if not shots:
            return ""
        figures: list[str] = ["<section><h2>Screenshots</h2>"]
        for s in shots[:20]:
            src = s.attributes.get("annotated") or s.value
            page = html.escape(str(s.attributes.get("page_type", "unknown")))
            figures.append(
                f'<figure><img src="{html.escape(str(src))}" alt="screenshot">'
                f"<figcaption>{html.escape(str(s.value))} — {page}</figcaption></figure>"
            )
        figures.append("</section>")
        return "\n".join(figures)


_RENDERERS = {r.format: r for r in (MarkdownRenderer(), HTMLRenderer(), JSONRenderer())}


def get_renderer(fmt: str):
    """Return a renderer for ``fmt`` (markdown/html/json)."""
    if fmt not in _RENDERERS:
        raise ConfigurationError(
            f"Unknown report format {fmt!r}. Available: {', '.join(_RENDERERS)}"
        )
    return _RENDERERS[fmt]
