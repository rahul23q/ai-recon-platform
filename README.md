# recon-platform

An AI-powered **Web Application Security Reconnaissance** platform for **authorized
security testing**. It behaves like an autonomous security consultant: it plans,
reasons, runs recon tools, remembers findings, builds a knowledge graph, and
generates professional reports.

> ⚠️ **Authorized use only.** Only run this against systems you own or have
> explicit written permission to test. Unauthorized scanning is illegal in most
> jurisdictions. The default profile performs *passive* reconnaissance.

---

## Status — Phase 4 (Desktop Automation Agent)

This repository contains the **Clean-Architecture foundation** plus the working
end-to-end workflow **Passive Recon → (Browser) → (Vision) → Verification →
(Desktop) → Analysis → Report**, driven by a multi-agent pipeline over a
structured Agent-to-Agent (A2A) message bus, with optional LangGraph
orchestration and Anthropic Claude reasoning. Phases 2–4 add opt-in **Browser**
(Playwright + Chrome DevTools), **Vision** (OCR + visual intelligence) and
**Desktop** (mouse / keyboard / windows / clipboard / screen capture) agents
behind the same `Agent` Protocol; all are off by default so the platform still
runs fully offline. A **Verification** stage corroborates passive findings
against the browser so results are graded Verified / Likely / Needs-Verification
/ False Positive instead of over-reported.

It is designed to grow module-by-module (active recon, browser/vision agents,
more plugins, the live dashboard) without changing the existing layers.

```
            ┌──────────────────────────────────────────────────────────────┐
            │                        Orchestration                          │
            │   LangGraph state machine  (fallback: sequential pipeline)    │
            └───────────────┬──────────────────────────────────────────────┘
                            │  A2A structured messages (bus)
   ┌─────────┬─────────────┼───────────────┬──────────────┬────────────────┐
   ▼         ▼             ▼               ▼              ▼                ▼
Planner   Recon        Analysis        Reporting     (Memory)        (Knowledge
Agent     Agent         Agent           Agent         Agent            Graph Agent)
   │         │                                          
   │         └── Recon modules (DNS, HTTP headers, robots, crt.sh CT,
   │             Wayback, tech fingerprint) via the Plugin / MCP registry
   │
   └── LLM reasoning (Claude): Thought → Plan → Action → Reflection
```

### What is implemented now

- **Clean Architecture / SOLID layering**: `domain` (entities + Protocol
  interfaces) ← `core` (config, DI container, logging) ← infrastructure
  (`llm`, `a2a`, `memory`, `knowledge_graph`, `recon`, `plugins`, `mcp`) ←
  `agents` ← `orchestration` / `api` / `cli`.
- **Async everywhere** (`asyncio`), dependency injection via a typed container,
  every component behind a `Protocol` so it is replaceable and testable.
- **A2A message bus**: structured envelopes (task, priority, reason, evidence,
  dependencies, result, confidence) with pub/sub topics.
- **Agents**: Planner (LLM or deterministic fallback), Recon, Analysis,
  Reporting, plus a base class encoding the
  Thought→Observation→Plan→Action→Reflection loop.
- **Passive recon modules** (pure-Python, no external binaries required) so the
  pipeline runs offline against your authorized targets.
- **Plugin + MCP tool registries**: uniform tool interface with name, schema,
  permissions — external tools (nmap, nuclei, subfinder, …) plug in here.
- **Layered memory** (short-term / working / long-term / episodic) and an
  in-process **knowledge graph** connecting domains, IPs, endpoints, techs…
- **Reporting**: Markdown / HTML / JSON renderers with executive + technical
  sections, OWASP/severity mapping hooks.
- **FastAPI + WebSocket** app exposing runs and a live event stream.
- **Typer CLI**: `recon passive-recon <target>` (and `recon browse <target>`).
- **Browser Agent** (Phase 2, opt-in): a Playwright + Chrome DevTools agent that
  navigates in a real headless Chromium, captures network requests, response
  headers, cookies, scripts and same-origin links, and saves screenshot evidence
  — with retry + browser-restart self-healing. Discovered assets flow into the
  same knowledge graph and reporting; insecure-cookie and capture findings are
  added by Analysis.
- **Vision Agent** (Phase 3, opt-in): an OCR + visual-intelligence agent that
  reads the Browser agent's screenshots, performs provider-independent OCR
  (EasyOCR / RapidOCR / PaddleOCR), detects elements (buttons, forms, login,
  search, navigation, captcha, cookie banners, MFA, errors, popups), classifies
  pages (login / admin / dashboard / Swagger / GraphQL / CMS / error / payment /
  API-docs), extracts on-screen text, emails, phones, URLs and secrets, and reads
  QR codes — emitting screenshot-backed findings and a Visual Intelligence report
  section.
- **Desktop Agent** (Phase 4, opt-in): an OS-automation agent for scenarios
  beyond the browser — window discovery/management, screen capture, clipboard,
  and (gated) synthetic mouse/keyboard input including file-upload/download
  dialogs. It reuses the Vision agent's detected on-screen elements to click "by
  sight". Provider-independent input backend (`null` recorder + `pyautogui`),
  behind a two-key safety posture: enabling it allows observation only, while
  real input additionally requires `RECON_DESKTOP__ALLOW_INPUT`. Off by default
  and degrades to a clean no-op without the `desktop` extra or a display.

---

## Browser Agent (Phase 2)

The Browser Agent is **off by default**. Enable it by installing the extra and
its Chromium binary, then pass `--browser` (or use the `browse` command):

```bash
pip install -e ".[browser]"        # adds Playwright
playwright install chromium        # one-time browser download

# Passive recon plus the browser pass:
recon passive-recon example.com --browser

# Browser-focused convenience command (enables the agent for you):
recon browse example.com

# Or enable it via the environment / API:
RECON_BROWSER__ENABLED=1 recon tools          # lists the browser.* tools
# API:  POST /runs {"target": "example.com", "browser": true}
```

If Playwright is not installed (or the browser is disabled), the browser step
**degrades to a clean no-op** and records a skip trace — the passive pipeline is
unaffected. Screenshots are written under `reports/screenshots/` by default
(`RECON_BROWSER__SCREENSHOT_DIR`).

---

## Vision Agent (Phase 3)

The Vision Agent is **off by default**. It analyzes the screenshots the Browser
agent captures (so enabling vision implies the browser), running OCR + element
detection + page classification:

```bash
pip install -e ".[browser,vision]"     # Playwright + OCR/vision stack
playwright install chromium

# Browser + Vision in one go:
recon vision example.com

# Or add vision to a passive run (implies --browser):
recon passive-recon example.com --vision

# Enable via the environment / API:
RECON_VISION__ENABLED=1 recon tools             # lists the vision.* tools
# API:  POST /runs {"target": "example.com", "vision": true}
```

The OCR engine is selectable and provider-independent
(`RECON_VISION__OCR_PROVIDER=easyocr|rapidocr|paddleocr`); an unknown or
uninstalled engine falls back to a null provider so a run never crashes. When no
vision backend is installed at all, the vision step **degrades to a clean no-op**
and records a skip trace. Annotated screenshots (bounding boxes) are written
under `reports/vision/` (`RECON_VISION__ANNOTATE_DIR`).

---

## Desktop Agent (Phase 4)

The Desktop Agent is **off by default** and behind a *two-key* safety posture, so
the platform stays passive. Enabling it permits **read-only observation** (window
discovery, screen capture, clipboard read); sending **real synthetic input**
(mouse/keyboard, file dialogs) additionally requires `allow_input`. Until then,
interactions are recorded as **planned (dry-run)** actions — fully auditable, with
the cursor never moving.

```bash
pip install -e ".[desktop]"        # pyautogui + pygetwindow + pyperclip + mss

# Observe-only desktop pass (windows / capture / clipboard; clicks are dry-run):
recon desktop example.com

# Let the Desktop agent act on Vision-detected on-screen elements:
recon desktop example.com --with-vision        # implies browser + vision

# Add desktop to a passive run:
recon passive-recon example.com --desktop

# Enable real input + via the environment / API:
RECON_DESKTOP__ENABLED=1 RECON_DESKTOP__ALLOW_INPUT=1 recon tools   # lists desktop.* tools
# API:  POST /runs {"target": "example.com", "desktop": true}
```

When no desktop backend is installed (or there is no display server), the desktop
step **degrades to a clean no-op** and records a skip trace — the pipeline is
unaffected. Desktop screenshots are written under `reports/desktop/`
(`RECON_DESKTOP__SCREENSHOT_DIR`). The agent reuses the Vision agent's detected
`VISUAL_ELEMENT` bounding boxes to click "by sight" rather than at hard-coded
coordinates.

> ⚠️ Synthetic input drives the *local* machine running the platform. Only enable
> `allow_input` in an environment you control and are authorized to automate.

---

## Cross-source verification

HTTP header analysis is **case-insensitive** and runs only on the **final**
response after redirects (intermediate 301/302 responses are never analyzed), and
each finding records both header presence and value. A dedicated **Verification**
stage then corroborates the passive view against the Browser agent's in-browser
view, which removes a real class of false positives — many servers send headers
like `Content-Security-Policy` only to browser-like clients, so a passive-only
fetch can wrongly report them missing.

Every finding carries a **verification status**, a **confidence score**, and its
**verification sources** (e.g. `passive-http`, `browser`):

| Status | Meaning |
|---|---|
| **Verified** | Independent sources agree (e.g. passive HTTP + browser). |
| **Likely** | Single-source, deterministic, not yet cross-verified. |
| **Needs Manual Verification** | Sources disagree — confirm on the live target. |
| **False Positive** | A claim refuted by a more authoritative source (e.g. a header "missing" in passive HTTP but present in the browser). |

Reports group findings into **Verified Findings**, **Likely Findings**, **Needs
Manual Verification**, and **False Positives**. Enable the Browser agent
(`--browser` / `--vision`) to upgrade single-source "likely" results to verified.

---

## Quick start

```bash
cd recon-platform
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -e ".[llm,api,dev]"                        # or just ".[dev]" to run offline

cp .env.example .env                                   # optional; add ANTHROPIC_API_KEY for LLM planning

# Run the passive recon workflow end-to-end (offline-capable):
recon passive-recon example.com

# Write a report to disk:
recon passive-recon example.com --report-format markdown --out reports/example.md

# Run the API + live dashboard:
uvicorn recon_platform.api.app:create_app --factory --reload
# then POST /runs {"target": "example.com"} and watch GET /ws
```

Without `ANTHROPIC_API_KEY`, the Planner uses a deterministic plan and everything
still runs. With a key, the Planner and Analysis agents reason with Claude
(`claude-sonnet-4-6` by default, configurable via `RECON_LLM__MODEL`).

---

## Testing

```bash
pip install -e ".[dev]"
pytest
```

---

## Roadmap (next slices)

1. ✅ Browser Agent (Playwright) with self-healing — **done (Phase 2)**.
2. ✅ Vision Agent (OCR + visual intelligence) — **done (Phase 3)**.
3. ✅ Desktop Agent (mouse/keyboard/windows/clipboard, click-by-sight) — **done (Phase 4)**.
4. Active recon workflow + external tool plugins (httpx, subfinder, nuclei).
5. Network/API agents (JWT, GraphQL, WebSocket inspection).
6. Live dashboard UI, Redis/Postgres persistence, Celery distributed workers.
7. Reporting: PDF/DOCX, OWASP/MITRE ATT&CK/CWE/CVSS mapping.

See `docs/` (to be added) and inline module docstrings for extension points.
