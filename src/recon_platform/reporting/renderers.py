"""Report renderers.

Each renderer implements the `ReportRenderer` Protocol (``format`` + ``render``)
and turns a `ReportBundle` into a concrete document. Phase 1 ships Markdown,
HTML, and JSON; PDF/DOCX renderers slot in behind the same Protocol later.
"""

from __future__ import annotations

import html

from recon_platform.core.exceptions import ConfigurationError
from recon_platform.domain.schemas import ReportBundle

_SECTION_ORDER = ["critical", "high", "medium", "low", "info"]


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

        # Findings
        lines.append("## Findings")
        lines.append("")
        if not bundle.findings:
            lines.append("_No findings._")
            lines.append("")
        for f in bundle.findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            lines.append(f"### [{sev.upper()}] {f.title}")
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


class HTMLRenderer:
    format = "html"

    def render(self, bundle: ReportBundle) -> str:
        md = MarkdownRenderer().render(bundle)
        # Minimal, dependency-free HTML wrapper preserving the Markdown as text.
        body = html.escape(md)
        eng = bundle.engagement
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
</style>
</head>
<body>
<header><h1>Recon Report — {html.escape(eng.target)}</h1></header>
<pre>{body}</pre>
</body>
</html>"""


_RENDERERS = {r.format: r for r in (MarkdownRenderer(), HTMLRenderer(), JSONRenderer())}


def get_renderer(fmt: str):
    """Return a renderer for ``fmt`` (markdown/html/json)."""
    if fmt not in _RENDERERS:
        raise ConfigurationError(
            f"Unknown report format {fmt!r}. Available: {', '.join(_RENDERERS)}"
        )
    return _RENDERERS[fmt]
