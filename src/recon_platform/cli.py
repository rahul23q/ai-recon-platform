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


def _settings_for(
    browser: bool,
    vision: bool = False,
    desktop: bool = False,
    active: bool = False,
    network: bool = False,
    api: bool = False,
    js: bool = False,
) -> Settings:
    """Build a fresh Settings with the optional agents toggled.

    Vision analyzes the Browser agent's screenshots, so enabling vision implies
    enabling the browser too. The desktop agent is independent, but it can act on
    the Vision agent's detected on-screen elements when both are enabled.

    ``active`` turns the active-recon agent *on*, but its **second** safety key
    (``RECON_ACTIVE_RECON__AUTHORIZED``) and the engagement authorization gate are
    deliberately left to the environment — the flag alone never starts an intrusive
    scan. Without the second key the active step records a clean skip.

    ``network`` turns on the passive network-analysis agent (JWT / CORS / API /
    WebSocket correlation over already-captured data); it issues no new I/O.
    """
    settings = Settings()
    settings.browser.enabled = browser or vision
    settings.vision.enabled = vision
    settings.desktop.enabled = desktop
    settings.active_recon.enabled = active
    settings.network.enabled = network
    settings.api_discovery.enabled = api
    settings.js_analysis.enabled = js
    return settings


app = typer.Typer(
    add_completion=False,
    help="AI-powered web-app security recon (authorized testing only).",
)
# legacy_windows=False routes output through the standard (now UTF-8) stream
# instead of the cp1252-bound Win32 console writer.
console = Console(legacy_windows=False)


async def _execute(
    target: str,
    report_format: str,
    out: pathlib.Path | None,
    browser: bool = False,
    vision: bool = False,
    desktop: bool = False,
    active: bool = False,
    network: bool = False,
    api: bool = False,
    js: bool = False,
) -> int:
    # An explicit Settings (built only when needed) lets the optional-agent flags
    # flip the otherwise-default-off agents without touching the cached
    # process-wide settings singleton.
    _optional = browser or vision or desktop or active or network or api or js
    container = (
        build_container(_settings_for(browser, vision, desktop, active, network, api, js))
        if _optional
        else build_container()
    )
    orch = ReconOrchestrator(container)
    engagement = EngagementContext(target=target, workflow=WorkflowType.PASSIVE_RECON)

    label = (
        "JavaScript analysis"
        if js
        else "API discovery"
        if api
        else "Network recon"
        if network
        else "Active recon"
        if active
        else "Desktop recon"
        if desktop
        else "Vision recon"
        if vision
        else "Browser recon"
        if browser
        else "Passive recon"
    )
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
    vision: bool = typer.Option(
        False,
        "--vision/--no-vision",
        help="Also run the Vision agent over screenshots (implies --browser; "
        "requires the 'vision' extra).",
    ),
    desktop: bool = typer.Option(
        False,
        "--desktop/--no-desktop",
        help="Also run the Desktop agent (windows / capture / clipboard; gated "
        "input). Requires the 'desktop' extra; off by default.",
    ),
    active: bool = typer.Option(
        False,
        "--active/--no-active",
        help="Also run the Active-Recon agent (external tools: httpx, subfinder, "
        "nuclei, nmap, …). Intrusive: additionally requires "
        "RECON_ACTIVE_RECON__AUTHORIZED=1 and an authorized target; off by default.",
    ),
    network: bool = typer.Option(
        False,
        "--network/--no-network",
        help="Also run the Network agent (passive JWT / CORS / API / WebSocket "
        "analysis over captured traffic). No new I/O; off by default.",
    ),
    api: bool = typer.Option(
        False,
        "--api/--no-api",
        help="Also run the API-Discovery agent (passive REST / GraphQL / SOAP / "
        "gRPC characterization + auth-scheme detection). No new I/O; off by default.",
    ),
    js: bool = typer.Option(
        False,
        "--js/--no-js",
        help="Also run the JS-Analysis agent (passively fetch + analyze scripts for "
        "endpoints, secrets, and source maps). GET-only fetch; off by default.",
    ),
) -> None:
    """Run the passive reconnaissance workflow end-to-end."""
    code = asyncio.run(
        _execute(
            target,
            report_format,
            out,
            browser=browser,
            vision=vision,
            desktop=desktop,
            active=active,
            network=network,
            api=api,
            js=js,
        )
    )
    raise typer.Exit(code)


@app.command("vision")
def vision(
    target: str = typer.Argument(..., help="Authorized domain or host to analyze."),
    report_format: str = typer.Option(
        "markdown", "--report-format", "-f", help="markdown | html | json"
    ),
    out: pathlib.Path | None = typer.Option(
        None, "--out", "-o", help="Write the report to this file instead of stdout."
    ),
) -> None:
    """Run the workflow with the Browser + Vision agents enabled.

    Install the extras first: ``pip install '.[browser,vision]'`` (and
    ``playwright install chromium``). Without them, the browser/vision steps
    degrade to clean no-ops. The Vision agent performs OCR and element detection
    over the screenshots the Browser agent captures.
    """
    code = asyncio.run(_execute(target, report_format, out, browser=True, vision=True))
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


@app.command("desktop")
def desktop(
    target: str = typer.Argument(..., help="Authorized domain or host for the engagement."),
    report_format: str = typer.Option(
        "markdown", "--report-format", "-f", help="markdown | html | json"
    ),
    out: pathlib.Path | None = typer.Option(
        None, "--out", "-o", help="Write the report to this file instead of stdout."
    ),
    with_vision: bool = typer.Option(
        False,
        "--with-vision/--no-with-vision",
        help="Also run Browser + Vision so the Desktop agent can act on detected "
        "on-screen elements (requires the 'browser,vision' extras).",
    ),
) -> None:
    """Run the workflow with the Desktop agent enabled.

    Install the extra first: ``pip install '.[desktop]'``. Without it (or without
    a display server), the desktop step degrades to a clean no-op. Synthetic
    mouse/keyboard input stays disabled unless ``RECON_DESKTOP__ALLOW_INPUT=1`` is
    set — by default the agent only observes (windows, screen capture, clipboard)
    and records *planned* interactions.
    """
    code = asyncio.run(
        _execute(target, report_format, out, vision=with_vision, desktop=True)
    )
    raise typer.Exit(code)


@app.command("active-recon")
def active_recon(
    target: str = typer.Argument(..., help="Authorized domain or host to actively scan."),
    report_format: str = typer.Option(
        "markdown", "--report-format", "-f", help="markdown | html | json"
    ),
    out: pathlib.Path | None = typer.Option(
        None, "--out", "-o", help="Write the report to this file instead of stdout."
    ),
) -> None:
    """Run the workflow with the Active-Recon agent enabled (external tools).

    Active recon is **intrusive** and behind a *two-key* posture. This command
    turns the agent on (the first key); it actually scans only when the **second**
    key and the engagement gate are also satisfied:

      * ``RECON_ACTIVE_RECON__AUTHORIZED=1`` — explicit acknowledgment that you are
        permitted to actively scan the target, and
      * the target passes the authorization gate (``RECON_AUTHORIZED_TARGETS`` /
        ``RECON_AUTHORIZED_ONLY``).

    Tools (httpx, subfinder, amass, naabu, nmap, katana, gau, dirsearch, ffuf,
    nuclei) are discovered on ``PATH`` and never imported, so any that are not
    installed are skipped cleanly. Without the second key the step is a no-op.
    """
    code = asyncio.run(_execute(target, report_format, out, active=True))
    raise typer.Exit(code)


@app.command("network")
def network(
    target: str = typer.Argument(..., help="Authorized domain or host to analyze."),
    report_format: str = typer.Option(
        "markdown", "--report-format", "-f", help="markdown | html | json"
    ),
    out: pathlib.Path | None = typer.Option(
        None, "--out", "-o", help="Write the report to this file instead of stdout."
    ),
    with_browser: bool = typer.Option(
        True,
        "--with-browser/--no-with-browser",
        help="Also run the Browser agent so more request/response traffic is "
        "captured for the Network agent to analyze (requires the 'browser' extra).",
    ),
) -> None:
    """Run the workflow with the Network agent enabled.

    The Network agent is a **passive** correlation layer: it inspects JWTs, CORS
    headers, API traffic (GraphQL / REST), and WebSocket endpoints found in data
    already captured by passive recon and the Browser agent — it issues no new
    requests. Enabling the Browser agent (the default here) captures richer
    traffic to analyze; pass ``--no-with-browser`` to analyze passive-recon data
    only.
    """
    code = asyncio.run(
        _execute(target, report_format, out, browser=with_browser, network=True)
    )
    raise typer.Exit(code)


@app.command("api-discovery")
def api_discovery(
    target: str = typer.Argument(..., help="Authorized domain or host to analyze."),
    report_format: str = typer.Option(
        "markdown", "--report-format", "-f", help="markdown | html | json"
    ),
    out: pathlib.Path | None = typer.Option(
        None, "--out", "-o", help="Write the report to this file instead of stdout."
    ),
    with_browser: bool = typer.Option(
        True,
        "--with-browser/--no-with-browser",
        help="Also run the Browser agent so more endpoints/headers are captured for "
        "the API-Discovery agent to characterize (requires the 'browser' extra).",
    ),
) -> None:
    """Run the workflow with the API-Discovery agent enabled.

    The API-Discovery agent is a **passive** characterization layer: it infers
    REST APIs (base path / version / resources / parameters), discovers GraphQL /
    SOAP / gRPC services, and detects authentication schemes from endpoints and
    headers already captured by passive recon, the Browser agent, and the Network
    agent — it issues no new requests. Enabling the Browser agent (the default
    here) captures a richer surface; pass ``--no-with-browser`` to analyze
    passive-recon data only. The Network agent is enabled alongside it so its
    GraphQL/REST traffic classification feeds discovery.
    """
    code = asyncio.run(
        _execute(target, report_format, out, browser=with_browser, network=True, api=True)
    )
    raise typer.Exit(code)


@app.command("js-analysis")
def js_analysis(
    target: str = typer.Argument(..., help="Authorized domain or host to analyze."),
    report_format: str = typer.Option(
        "markdown", "--report-format", "-f", help="markdown | html | json"
    ),
    out: pathlib.Path | None = typer.Option(
        None, "--out", "-o", help="Write the report to this file instead of stdout."
    ),
    with_browser: bool = typer.Option(
        True,
        "--with-browser/--no-with-browser",
        help="Also run the Browser agent to inventory <script src> URLs for the "
        "JS-Analysis agent to fetch (requires the 'browser' extra).",
    ),
) -> None:
    """Run the workflow with the JS-Analysis agent enabled.

    The JS-Analysis agent maps the client-side attack surface: it **passively
    fetches** (GET-only) the JavaScript the target serves and extracts endpoints,
    request parameters, embedded secrets, and source-map references. It relies on
    ``JS_FILE`` assets discovered by the Browser agent (enabled by default here;
    pass ``--no-with-browser`` to analyze only scripts found by passive recon).
    JS-sourced endpoints then feed the Network and API-discovery agents, which run
    alongside it.
    """
    code = asyncio.run(
        _execute(
            target, report_format, out, browser=with_browser, network=True, api=True, js=True
        )
    )
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
