"""Command-line interface (Typer).

    recon passive-recon example.com
    recon passive-recon example.com --report-format markdown --out report.md
    recon tools
    recon version

Runs the orchestrator and streams live agent events, then renders the report.
Works fully offline; add ANTHROPIC_API_KEY to enable Claude-backed reasoning.
"""

from __future__ import annotations

import asyncio
import pathlib
import sys

import typer
from rich.console import Console
from rich.table import Table

from recon_platform import __version__
from recon_platform.bootstrap import build_container
from recon_platform.core.config import Settings
from recon_platform.core.exceptions import ReconPlatformError
from recon_platform.domain.enums import WorkflowType
from recon_platform.domain.interfaces import ToolRegistry
from recon_platform.domain.schemas import EngagementContext
from recon_platform.orchestration.graph import ReconOrchestrator
from recon_platform.reporting.renderers import get_renderer


def _force_utf8_streams() -> None:
    """Make output robust on legacy Windows consoles (cp1252) by forcing UTF-8."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            pass


_force_utf8_streams()


def _settings_for(browser: bool) -> Settings:
    """Build a fresh Settings with the browser agent toggled for this run."""
    settings = Settings()
    settings.browser.enabled = browser
    return settings


app = typer.Typer(
    add_completion=False,
    help="AI-powered web-app security recon (authorized testing only).",
)
# legacy_windows=False routes output through the standard (now UTF-8) stream
# instead of the cp1252-bound Win32 console writer.
console = Console(legacy_windows=False)


async def _execute(
    target: str, report_format: str, out: pathlib.Path | None, browser: bool = False
) -> int:
    # An explicit Settings (built only when needed) lets the browser flag flip
    # the otherwise-default-off browser agent without touching the cached
    # process-wide settings singleton.
    container = build_container(_settings_for(browser)) if browser else build_container()
    orch = ReconOrchestrator(container)
    engagement = EngagementContext(target=target, workflow=WorkflowType.PASSIVE_RECON)

    label = "Browser recon" if browser else "Passive recon"
    console.rule(f"[bold]{label} — {target}")

    run_task = asyncio.create_task(orch.run(engagement))

    # Stream live events while the run proceeds.
    async for event in orch.stream_events():
        kind = event.get("event")
        if kind == "run.start":
            console.print(
                f"[green]▶[/] run started "
                f"(LLM reasoning: {'on' if event.get('llm') else 'off — deterministic'})"
            )
        elif kind == "step":
            console.print(f"[cyan]●[/] step: [bold]{event['name']}[/]")
        elif kind == "a2a":
            recipient = event.get("recipient") or "broadcast"
            console.print(
                f"   [dim]{event['sender']} → {recipient}:[/] {event['reason']}"
            )
        elif kind == "run.complete":
            console.print(
                f"[green]✔[/] complete — "
                f"{event['assets']} assets, {event['findings']} findings"
            )

    try:
        bundle = await run_task
    except ReconPlatformError as exc:
        console.print(f"[red]error:[/] {exc}")
        return 2

    rendered = get_renderer(report_format).render(bundle)
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(rendered, encoding="utf-8")
        console.print(f"[green]✔[/] report written to [bold]{out}[/]")
    else:
        console.rule("[bold]Report")
        # Markdown reads fine as plain text in a terminal.
        console.print(rendered if report_format != "json" else rendered, markup=False)
    return 0


@app.command("passive-recon")
def passive_recon(
    target: str = typer.Argument(..., help="Authorized domain or host to scan."),
    report_format: str = typer.Option(
        "markdown", "--report-format", "-f", help="markdown | html | json"
    ),
    out: pathlib.Path | None = typer.Option(
        None, "--out", "-o", help="Write the report to this file instead of stdout."
    ),
    browser: bool = typer.Option(
        False,
        "--browser/--no-browser",
        help="Also run the Playwright browser agent (requires the 'browser' extra).",
    ),
) -> None:
    """Run the passive reconnaissance workflow end-to-end."""
    code = asyncio.run(_execute(target, report_format, out, browser=browser))
    raise typer.Exit(code)


@app.command("browse")
def browse(
    target: str = typer.Argument(..., help="Authorized domain or host to browse."),
    report_format: str = typer.Option(
        "markdown", "--report-format", "-f", help="markdown | html | json"
    ),
    out: pathlib.Path | None = typer.Option(
        None, "--out", "-o", help="Write the report to this file instead of stdout."
    ),
) -> None:
    """Run the workflow with the browser agent enabled (Playwright required).

    Install the extra first: ``pip install '.[browser]' && playwright install
    chromium``. Without it, the browser step degrades to a clean no-op.
    """
    code = asyncio.run(_execute(target, report_format, out, browser=True))
    raise typer.Exit(code)


@app.command("tools")
def list_tools() -> None:
    """List capabilities registered in the MCP tool catalogue."""
    container = build_container()
    registry = container.resolve(ToolRegistry)  # type: ignore[type-abstract]
    table = Table(title="MCP tool catalogue")
    table.add_column("name", style="cyan")
    table.add_column("permissions")
    table.add_column("description")
    for descriptor in registry.describe():  # type: ignore[attr-defined]
        table.add_row(
            descriptor["name"],
            ", ".join(descriptor["permissions"]),
            descriptor["description"],
        )
    console.print(table)


@app.command("version")
def version() -> None:
    """Print the platform version."""
    console.print(f"recon-platform {__version__}")


if __name__ == "__main__":
    app()
