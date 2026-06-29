# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/).

## [0.3.0] — 2026-06-29

### Phase 3 — Vision Agent (Completed)

An OCR + visual-intelligence **Vision Agent** that understands web pages from the
screenshots the Browser agent captures, wired behind the existing `Agent`
Protocol and orchestrator without rewriting any Phase-1/2 layer. Opt-in and off
by default; degrades to a clean no-op when disabled or when no vision backend is
installed. Pipeline is now Planner → Recon → Browser → **Vision** → Analysis →
Reporting.

#### Added

- **Vision infrastructure** (`vision/`): provider-independent `OCRProvider`
  (EasyOCR / RapidOCR / PaddleOCR, with an always-available null fallback and a
  name-based factory), a dependency-free `HeuristicDetector` + page classifier +
  text extractors (emails, phones, URLs, internal hosts, JWT/AWS/Google/GitHub/
  Slack secrets), a `VisionSession` (lazy image stack, OCR → detection →
  classification → OpenCV QR scan, best-effort bounding-box annotation), and a
  `VisionModelProvider` interface for future GPT-4V / Claude / Gemini / Qwen-VL.
- **Vision modules**: `screenshot_ingest` (→ `SCREENSHOT` assets + cached
  analysis + page classification), `ocr_text` (page text, headings, emails, URLs,
  internal endpoints, phones, secrets), `object_detection` (→ `VISUAL_ELEMENT`
  with `element_type` button/form/login/search/nav/captcha/cookie/MFA/error/popup),
  and `qr_codes` (→ `QR_CODE`).
- **Asset types**: `SCREENSHOT`, `VISUAL_ELEMENT`, `TEXT_REGION`, `QR_CODE`, and a
  `DEPICTS` relation linking a screenshot to the page it shows.
- **`VisionAgent`**: reuses Browser screenshots (never re-captures), populates the
  graph, records a trace per module, and emits `vision.started` / `vision.ocr` /
  `vision.object_detected` / `vision.qr_detected` / `vision.completed` A2A events.
- **Orchestration**: an independent `vision` step between browser and analysis
  (sequential path + LangGraph node) that runs only when enabled; the Planner's
  3-task plan is untouched.
- **Analysis**: additive rules for exposed secrets in screenshots (HIGH),
  sensitive on-screen information / PII / internal URLs, visually-identified
  login / admin / payment pages, login-without-MFA, and a visual-capture summary.
- **Reporting**: a "Visual Intelligence" section (page types, element counts, OCR
  provider, annotated paths) and an embedded screenshot gallery in HTML.
- **Tooling & surfaces**: `VisionPlugin` (`plugins/vision.py`) exposes the vision
  modules in the MCP catalogue when enabled; `recon passive-recon --vision` and a
  new `recon vision <target>` command (both imply the browser agent); a `vision`
  flag on the API `RunRequest`; `RECON_VISION__*` settings.
- **Tests**: hermetic vision tests (no OCR model downloads, no image libraries) —
  pure-function coverage for the detector / classifier / extractors plus
  disabled-by-default, enabled-stubbed, and graceful-degradation pipeline tests.

[0.3.0]: https://github.com/OWNER/recon-platform/releases/tag/v0.3.0

## [0.2.0] — 2026-06-29

### Phase 2 — Browser Agent (Completed)

A Playwright + Chrome DevTools **Browser Agent**, wired behind the existing
`Agent` Protocol and orchestrator without rewriting any Phase-1 layer. Opt-in and
off by default; degrades to a clean no-op when disabled or when Playwright is not
installed, so the offline foundation is unaffected.

#### Added

- **Browser infrastructure** (`browser/`): `BrowserModule`/`BrowserContext`
  base, a `BrowserSession` async context manager wrapping the Playwright
  lifecycle (lazy import, headless Chromium, network/cookie capture, screenshot
  evidence, and retry + browser-restart self-healing on navigation crash).
- **Browser modules**: `navigation` (real-browser page load → `URL` asset +
  screenshot), `network_capture` (same-origin requests → `ENDPOINT`, response
  headers → `HEADER`), `cookies` (→ `COOKIE` with Secure/HttpOnly/SameSite
  flags), `script_inventory` (→ `JS_FILE`), and `dom_links` (same-origin links /
  form actions → `ENDPOINT`).
- **`BrowserAgent`**: drives the session, populates the knowledge graph, records
  a reasoning trace per module, and announces work on the A2A bus — mirroring
  `ReconAgent`.
- **Orchestration**: an independent `browser` step between recon and analysis
  (sequential path + LangGraph node) that runs only when enabled and leaves the
  Planner's 3-task plan untouched.
- **Analysis**: additive rules for insecure cookies (missing Secure / HttpOnly /
  SameSite) and a browser-capture summary carrying screenshot evidence.
- **Tooling & surfaces**: `BrowserPlugin` exposes the browser modules in the MCP
  catalogue (registered only when enabled); `recon passive-recon --browser` and a
  new `recon browse <target>` command; a `browser` flag on the API `RunRequest`;
  `RECON_BROWSER__*` settings.
- **Tests**: hermetic browser tests (no real Chromium / Playwright) covering
  disabled-by-default no-op, enabled-stubbed asset/finding flow, and graceful
  degradation when Playwright is absent.

[0.2.0]: https://github.com/OWNER/recon-platform/releases/tag/v0.2.0

## [0.1.0] — 2026-06-28

### Phase 1 — Foundation (Completed)

The Clean-Architecture foundation plus one fully working end-to-end workflow:
**Passive Recon → Analysis → Report**.

#### Added

- **Architecture**: layered domain / core / infrastructure / agents /
  orchestration design; `Protocol`-based contracts; typed dependency-injection
  container; fully asynchronous (`asyncio`).
- **A2A message bus**: in-memory pub/sub with topic routing, request/response
  correlation, and a full message-history timeline.
- **Agents**: Planner, Recon, Analysis, and Reporting, on a shared base agent
  encoding the Thought → Observation → Plan → Action → Reflection loop.
- **LLM reasoning**: Anthropic Claude via LangChain (`claude-sonnet-4-6` by
  default, adaptive thinking + effort), with a deterministic offline fallback so
  the platform runs without an API key.
- **Passive recon modules** (pure-Python, no external binaries): DNS, HTTP /
  security-header analysis, robots.txt, Certificate Transparency (crt.sh),
  Wayback Machine, and technology fingerprinting.
- **Knowledge graph**: in-process asset/relationship graph with dedup and merge.
- **Layered memory**: short-term / working / long-term / episodic scopes plus a
  reasoning-trace log.
- **Plugin system + MCP tool registry**: uniform tool contract (name,
  description, permissions, input/output schema); passive modules exposed as
  tools.
- **Orchestration**: LangGraph state machine with a guaranteed sequential
  fallback; live event stream for dashboards.
- **Reporting**: Markdown, HTML, and JSON renderers (executive + technical
  sections, severity counts, evidence, reasoning appendix).
- **Interfaces**: FastAPI app with WebSocket live event stream; Typer CLI
  (`recon passive-recon`, `recon tools`, `recon version`).
- **Safety**: authorization gate (`RECON_AUTHORIZED_ONLY`,
  `RECON_AUTHORIZED_TARGETS`); passive-by-default posture.
- **Quality**: 14 passing tests (domain, authorization, knowledge graph, bus,
  analysis rules, full offline pipeline, event stream); ruff-clean.
- **Project**: packaging (`pyproject.toml`), Docker / docker-compose,
  `.env.example`, README, LICENSE (MIT), CONTRIBUTING, SECURITY.

### Roadmap (not in this release)

Active recon + external tool plugins (httpx, subfinder, nuclei, …), Browser
(Playwright) and Vision (OpenCV/EasyOCR) agents with self-healing, Network/API
agents, a live dashboard UI, Redis/Postgres persistence and Celery distributed
workers, and PDF/DOCX reports with OWASP/MITRE ATT&CK/CWE/CVSS mapping.

[0.1.0]: https://github.com/OWNER/recon-platform/releases/tag/v0.1.0
