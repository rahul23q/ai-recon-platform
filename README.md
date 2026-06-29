# recon-platform

An AI-powered **Web Application Security Reconnaissance** platform for **authorized
security testing**. It behaves like an autonomous security consultant: it plans,
reasons, runs recon tools, remembers findings, builds a knowledge graph, and
generates professional reports.

> ⚠️ **Authorized use only.** Only run this against systems you own or have
> explicit written permission to test. Unauthorized scanning is illegal in most
> jurisdictions. The default profile performs *passive* reconnaissance.

---

## Status — Phase 2 (Browser Agent)

This repository contains the **Clean-Architecture foundation** plus the working
end-to-end workflow **Passive Recon → (Browser) → Analysis → Report**, driven by a
multi-agent pipeline over a structured Agent-to-Agent (A2A) message bus, with
optional LangGraph orchestration and Anthropic Claude reasoning. Phase 2 adds an
opt-in **Browser Agent** (Playwright + Chrome DevTools) behind the same `Agent`
Protocol; it is off by default so the platform still runs fully offline.

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
2. Vision Agent (OpenCV/EasyOCR) for screen understanding and click-by-sight.
3. Active recon workflow + external tool plugins (httpx, subfinder, nuclei).
4. Network/API agents (JWT, GraphQL, WebSocket inspection).
5. Live dashboard UI, Redis/Postgres persistence, Celery distributed workers.
6. Reporting: PDF/DOCX, OWASP/MITRE ATT&CK/CWE/CVSS mapping.

See `docs/` (to be added) and inline module docstrings for extension points.
