# Project Status

> A living record of what is built, what is in progress, and what comes next.
> Update this file whenever a milestone or notable feature lands.

| | |
|---|---|
| **Project** | recon-platform — AI-powered Web App Security Reconnaissance |
| **Current version** | `0.2.0` |
| **Current phase** | **Phase 2 — Browser Agent ✅ Completed** |
| **Next milestone** | **Phase 3 — Vision Agent** |
| **Last updated** | 2026-06-29 |
| **Quality gates** | ✅ 17/17 tests passing · ✅ ruff clean · ✅ offline default run unchanged |

---

## ✅ Phase 1 — Foundation (Completed)

Delivered the Clean-Architecture foundation plus one fully working end-to-end
workflow: **Passive Recon → Analysis → Report**, runnable offline and verified
against a live target.

### Implemented features

**Architecture & core**
- Clean Architecture with strict inward dependencies; SOLID throughout.
- Typed dependency-injection container (`core/container.py`) + composition root
  (`bootstrap.py`).
- Pydantic-settings configuration with safe offline defaults (`core/config.py`).
- Structured logging (`structlog`) and a `ReconPlatformError` exception hierarchy.
- Fully asynchronous (`asyncio`).

**Domain**
- `Protocol` interfaces for every seam (`MessageBus`, `LLMProvider`, `Memory`,
  `KnowledgeGraph`, `Tool`, `ToolRegistry`, `Plugin`, `Agent`, `ReportRenderer`,
  `Orchestrator`, `Planner`).
- Pydantic entities: `A2AMessage`, `Task`, `Plan`, `Asset`, `Relation`,
  `Finding`, `Evidence`, `ReconResult`, `ReasoningTrace`, `ReportBundle`,
  `EngagementContext`.

**Multi-agent layer**
- `Planner`, `Recon`, `Analysis`, `Reporting` agents on a shared `BaseAgent`
  that encodes the Thought→Observation→Plan→Action→Reflection loop.
- Agents announce work as structured `A2AMessage`s (timeline/observability).

**Agent-to-Agent (A2A) messaging**
- In-memory pub/sub bus with topic routing, request/response correlation, and a
  full message-history timeline.

**LLM reasoning**
- Anthropic Claude via LangChain (adaptive thinking + effort), with a
  deterministic offline fallback so the platform runs without an API key.

**Reconnaissance (passive, pure-Python)**
- DNS resolution, HTTP + security-header analysis, robots.txt parsing,
  Certificate Transparency (crt.sh) subdomain enumeration, Wayback Machine URL
  collection, technology fingerprinting.
- Authorization gate (passive by default).

**Memory & knowledge graph**
- Layered memory (short-term / working / long-term / episodic) + reasoning-trace
  log.
- In-process knowledge graph with asset dedup/merge and typed relations.

**Plugins & MCP**
- Plugin system and MCP-style tool registry; passive modules exposed as tools
  with name, description, permissions, and input/output schema.

**Orchestration**
- LangGraph state machine with a guaranteed sequential fallback; live event
  stream for dashboards.

**Reporting & interfaces**
- Markdown / HTML / JSON renderers (executive + technical sections, severity
  counts, evidence, reasoning appendix).
- FastAPI app with WebSocket live event stream; Typer CLI (`passive-recon`,
  `tools`, `version`).

**Project & docs**
- Packaging (`pyproject.toml`), Docker / docker-compose, `.env.example`,
  README, LICENSE (MIT), CONTRIBUTING, SECURITY, CHANGELOG, CLAUDE.md, ROADMAP.

---

## ✅ Phase 2 — Browser Agent (Completed)

Added a **Browser Agent** (Playwright + Chrome DevTools Protocol) behind the
existing `Agent` Protocol and orchestrator, with **zero rewrites** of Phase-1
layers. Opt-in and off by default; degrades to a clean no-op when disabled or
when Playwright is not installed, so the offline foundation is unchanged.

### Implemented features

- **`browser/` infrastructure** mirroring `recon/`: `BrowserModule` /
  `BrowserContext` base and a `BrowserSession` async context manager wrapping the
  Playwright lifecycle — lazy import, headless Chromium, network/cookie capture
  via page events, screenshot evidence, and **retry + browser-restart
  self-healing** on navigation crash (recorded as `recovery_plan` in traces).
- **Browser modules**: `navigation`, `network_capture`, `cookies`,
  `script_inventory`, `dom_links` → `URL` / `ENDPOINT` / `HEADER` / `COOKIE` /
  `JS_FILE` assets, reusing the Phase-1 attribute shapes so existing Analysis
  rules apply unchanged.
- **`BrowserAgent`** drives the session, populates the knowledge graph, records a
  reasoning trace per module, and announces work on the A2A bus.
- **Orchestration**: an independent `browser` step (sequential + LangGraph node)
  between recon and analysis that runs only when enabled — the Planner's 3-task
  plan is untouched.
- **Analysis**: additive insecure-cookie and browser-capture rules.
- **Surfaces**: `BrowserPlugin` in the MCP catalogue (registered when enabled),
  `recon passive-recon --browser`, `recon browse <target>`, an API `browser` flag,
  and `RECON_BROWSER__*` settings.
- **Quality**: 17 passing tests (14 prior + 3 hermetic browser tests:
  disabled-by-default no-op, enabled-stubbed flow, graceful degradation);
  ruff-clean; default offline run verified unchanged.

---

## ⏭️ Next milestone — Phase 3: Vision Agent

Introduce a **Vision Agent** (OpenCV + EasyOCR) for screen understanding — read
UI text, detect elements, and click by sight when the DOM is unreliable —
establishing the perception layer used by self-healing (DOM → Vision → Human
escalation). See [ROADMAP.md](ROADMAP.md) for the full phase plan.

**Entry criteria:** Phase 2 green (met). **Do not** restart earlier phases or
regenerate completed code — extend via the existing seams.

---

## 📝 Future notes & progress updates

Add dated entries here as work proceeds. Newest first.

- **2026-06-29** — Phase 2 (Browser Agent) completed and verified (17 tests
  passing, ruff clean, default offline run unchanged). Browser is opt-in and
  off by default; released as `v0.2.0`.
- **2026-06-28** — Phase 1 completed and verified (14 tests passing, ruff clean,
  live end-to-end run). Repository prepared for public release (`v0.1.0`).
- _next entry…_
