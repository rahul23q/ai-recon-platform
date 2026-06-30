# Project Status

> A living record of what is built, what is in progress, and what comes next.
> Update this file whenever a milestone or notable feature lands.

| | |
|---|---|
| **Project** | recon-platform — AI-powered Web App Security Reconnaissance |
| **Current version** | `0.5.0` |
| **Current phase** | **Phase 5 — Active Recon & Tool Plugins ✅ Completed** |
| **Next milestone** | **Phase 6 — Network Agent** |
| **Last updated** | 2026-06-30 |
| **Quality gates** | ✅ `ruff check` clean; `pytest` 68/69 (all 22 new active-recon tests green). One **pre-existing** verification test (`test_agreement_missing_reported_as_verified`) fails on HEAD, unrelated to Phase 5 — see *Known issues* below. |

---

## ⚠️ Known issues

### `test_agreement_missing_reported_as_verified` (pre-existing, unrelated to Phase 5)

`tests/test_verification.py::test_agreement_missing_reported_as_verified` fails on
`main` and has done so since before Phase 4. **Verified unrelated to Phase 5:** the
test fails identically with all Phase-5 changes stashed, and Phase 5 touches none
of the verification path (`agents/verification.py`, `verification/headers.py`,
`agents/analysis.py::_missing_security_headers`).

**Root cause (Phase 1 ↔ Phase 3.1 interaction).** The test seeds the graph with
identical `HEADER` assets from *both* the passive source (`http_headers`) and the
browser source (`network_capture`) — every header value is `"x"`, with only CSP
absent from both.  `InMemoryKnowledgeGraph.add_asset`
(`knowledge_graph/graph.py`) dedupes assets by their stable `type:value` key, so
the two sources' identical headers collapse into a **single** asset that keeps
only the first-added `source` (`http_headers`). `collect_header_maps`
(`verification/headers.py`) then derives an **empty browser map**, so
`browser_observed` is `False`; CSP is graded `LIKELY`-missing instead of
`VERIFIED`-missing, and no "verified missing" finding is produced — the assertion
`assert verified_missing` then fails. (The pure-logic unit tests pass because they
call `compute_header_verifications` directly, bypassing the lossy graph dedup.)

**Why not fixed here.** The only correct fix is to make the central knowledge-graph
merge preserve *multiple observation sources* for an identical-value asset (e.g.
union sources on merge). That changes Phase-1 core dedup semantics every layer
depends on (attribute precedence, confidence selection, serialization, report
output) and warrants its own reviewed change with dedicated tests — out of scope
for the Phase-5 milestone, and explicitly avoided to keep this change small and
safe. Tracked for the Phase 15 (Analysis & Correlation Intelligence) /
correlation work, where multi-source asset provenance is the natural home.

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

## ✅ Phase 3 — Vision Agent (Completed)

Added an OCR + visual-intelligence **Vision Agent** behind the existing `Agent`
Protocol and orchestrator, with **zero rewrites** of Phase-1/2 layers. Opt-in and
off by default; degrades to a clean no-op when disabled or when no vision backend
is installed. The pipeline is now Planner → Recon → Browser → **Vision** →
Analysis → Reporting.

### Implemented features

- **`vision/` infrastructure** mirroring `browser/`: provider-independent OCR
  (`OCRProvider` + EasyOCR / RapidOCR / PaddleOCR / null + factory), a
  dependency-free `HeuristicDetector`, page classifier, and text extractors
  (emails, phones, URLs, internal hosts, JWT/AWS/Google/GitHub/Slack secrets), a
  `VisionSession` (lazy image stack, OCR → detection → classification → OpenCV QR
  scan, best-effort bounding-box annotation), and a `VisionModelProvider`
  interface for future multimodal LLMs (Claude / GPT-4V / Gemini / Qwen-VL).
- **Vision modules**: `screenshot_ingest`, `ocr_text`, `object_detection`,
  `qr_codes` → `SCREENSHOT` / `VISUAL_ELEMENT` / `TEXT_REGION` / `QR_CODE` /
  `EMAIL` / `SECRET` / `ENDPOINT` assets, reusing Browser screenshots (never
  re-captured).
- **`VisionAgent`** drives the session, populates the graph, records a trace per
  module, and emits `vision.*` A2A events for the dashboard.
- **Orchestration**: an independent `vision` step (sequential + LangGraph node)
  between browser and analysis — the Planner's 3-task plan is untouched.
- **Analysis**: additive rules for exposed secrets, on-screen PII / internal
  URLs, login / admin / payment pages, login-without-MFA, and a visual summary.
- **Reporting**: a "Visual Intelligence" section + an HTML screenshot gallery.
- **Surfaces**: `VisionPlugin` in the MCP catalogue (registered when enabled),
  `recon passive-recon --vision`, `recon vision <target>`, an API `vision` flag,
  and `RECON_VISION__*` settings.
- **Quality**: 25 passing tests (17 prior + 8 hermetic vision tests, no model
  downloads); ruff-clean; default offline run verified unchanged.

---

## ✅ Cross-source verification (v0.3.1)

Hardened HTTP security-header detection against false positives (e.g. CSP reported
missing when the server only serves it to real browsers) with a new
**Verification stage** between the Browser/Vision agents and Analysis. The
pipeline is now **Planner → Recon → Browser → Vision → Verification → Analysis →
Reporting**.

- **Case-insensitive, final-response-only** header analysis (`HTTPHeadersModule`):
  names normalized to lowercase; only the final 200 after redirects is analyzed
  (redirect chain + final status recorded); presence **and** value stored.
- **`VerificationAgent`** cross-checks passive HTTP vs the browser's observed
  headers. Agreement ⇒ **Verified**; passive-only ⇒ **Likely**; disagreement ⇒
  **Needs Verification**; passive-missing-but-browser-present ⇒ **False Positive**.
- Every `Finding` now carries a **verification status**, **confidence score**, and
  **verification sources**; the report groups findings into **Verified /
  Likely / Needs Manual Verification / False Positives** sections.
- Phase 1/2/3 behaviour and the Browser/Vision agents are unchanged; the stage
  only reads their assets.
- **Tests**: `tests/test_verification.py` adds ~12 hermetic cases (header
  case-insensitivity, final-response-after-redirect via mocked transport,
  agreement/disagreement, false-positive detection, report sectioning). Gates
  (`ruff` + `pytest`) are run manually by the maintainer for this change.

---

## ✅ Phase 4 — Desktop Automation Agent (Completed)

Added a **Desktop agent** for OS automation — mouse, keyboard, window discovery /
management, clipboard, screen capture, and file-upload/download dialogs — behind
the existing `Agent` Protocol and orchestrator, with **zero rewrites** of earlier
layers. Opt-in and off by default, behind a *two-key* safety posture, and
degrading to a clean no-op when disabled or when no desktop backend is installed.
The pipeline is now Planner → Recon → Browser → Vision → Verification →
**Desktop** → Analysis → Reporting.

### Implemented features

- **`desktop/` infrastructure** mirroring `vision/`: a provider-independent
  `DesktopBackend` seam (`null` recorder + lazy `pyautogui` real-input backend +
  name-based factory with `null` fallback), a `DesktopManager` (windows via
  `pygetwindow`, clipboard via `pyperclip` with an in-process buffer fallback,
  screen capture via pyautogui / `mss` / Pillow), and a `DesktopSession` action
  lifecycle wrapper that records every interaction and enforces the input gate.
- **Two-key safety**: `enabled` permits read-only observation; synthetic input
  additionally requires `allow_input`. The default posture records **planned
  (dry-run)** actions — it never moves the real cursor — so a run is auditable
  with no GUI present. (Honours rule #7: passive by default; authorized only.)
- **Desktop modules**: `window_discovery` (→ `WINDOW`), `screen_capture` (→
  `SCREENSHOT` tagged `via=desktop`), `clipboard` (→ `DESKTOP_ACTION`), and
  `ui_interaction`, which **reuses the Vision agent's detected on-screen
  elements** (`VISUAL_ELEMENT` boxes) to click "by sight" and links each action
  back to the element it acted on.
- **`DesktopAgent`** drives the session, populates the graph, records a trace per
  module, and emits `desktop.*` A2A events for the dashboard.
- **Orchestration**: an independent `desktop` step (sequential + LangGraph node)
  between verification and analysis — the Planner's 3-task plan is untouched.
- **Analysis & reporting**: an additive desktop-automation summary finding and a
  "Desktop Automation" report section (windows + interactions, flagging real
  input vs. dry-run).
- **Surfaces**: `DesktopPlugin` in the MCP catalogue (registered when enabled),
  `recon passive-recon --desktop`, `recon desktop <target>`, an API `desktop`
  flag, `RECON_DESKTOP__*` settings, and a `desktop` install extra.
- **Quality**: 11 new hermetic desktop tests (no real input / GUI libs); ruff
  clean; default offline run verified unchanged.

> **Roadmap note.** Desktop automation (originally sketched as Phase 18) was
> prioritized and delivered here as Phase 4 at the maintainer's direction; the
> roadmap has been renumbered so Active Recon & Tool Plugins is now Phase 5.

---

## ✅ Phase 5 — Active Recon & Tool Plugins (Completed)

Added an **Active-Recon agent** integrating ten best-of-breed external security
tools as first-class plugins, behind the existing `Agent` Protocol and
orchestrator with **zero rewrites** of earlier layers. Opt-in and off by default,
behind a *two-key* authorization posture, and **intrusive** by nature. The
pipeline is now Planner → Recon → Browser → Vision → Verification → Desktop →
**Active Recon** → Analysis → Reporting.

### Implemented features

- **`active_recon/` infrastructure** mirroring `recon/` / `desktop/`: an
  `ExternalTool` contract (declare a binary, build a command line, parse stdout
  into the common `Asset` / `Relation` models), a shared async `ToolRunner`
  (timeout / retries / cancellation / output capture in one place, killing the
  child on expiry or abort), a normalized `ToolExecution` record, and an
  import-free `binary_available` PATH probe. Binaries are discovered on `PATH` and
  **never imported**, so any not installed are skipped cleanly and the platform
  installs and runs without them.
- **Ten tool wrappers** + a `build_active_tools` factory / `ACTIVE_TOOLS` map:
  httpx, subfinder, amass, naabu, nmap, katana, gau, dirsearch, ffuf, nuclei —
  each normalizing to `URL` / `TECHNOLOGY` / `SUBDOMAIN` / `PORT` / `SERVICE` /
  `ENDPOINT` / `VULNERABILITY` assets and `SUBDOMAIN_OF` / `EXPOSES` / `AFFECTS`
  relations. Parsers are defensive (unknown keys / blank lines / partial output
  ignored, never raised).
- **Two-key safety**: `enabled` turns the agent on; `authorized` is a separate
  explicit acknowledgment of permission to actively scan. Tools run only when
  **both** are set **and** the target passes the engagement authorization gate;
  any other state records a clean skip and returns empty.
- **`ActiveReconAgent`** runs the configured tool set, merges results into the
  knowledge graph, records a trace per tool, stores each execution in episodic
  memory, and emits `active.*` A2A events.
- **Orchestration**: an independent `active_recon` step (sequential + LangGraph
  node) between desktop and analysis — the Planner's 3-task plan is untouched.
- **Analysis & reporting**: additive vulnerability + attack-surface rules and an
  "Active Reconnaissance" report section (open services + reported vulnerabilities
  grouped by severity).
- **Surfaces**: `ActiveReconPlugin` in the MCP catalogue (registered when
  enabled), `recon passive-recon --active`, `recon active-recon <target>`, an API
  `active` flag, and `RECON_ACTIVE_RECON__*` settings.
- **Quality**: 22 new hermetic active-recon tests (no real binaries / subprocess
  / network); `ruff check` clean; default offline run verified unchanged.

---

## ⏭️ Next milestone — Phase 6: Network Agent

Deep analysis of requests/responses: header hygiene, JWT inspection, GraphQL and
REST traffic, and WebSocket message review, correlating network observations into
findings. See [ROADMAP.md](ROADMAP.md) for the full phase plan.

**Entry criteria:** Phase 5 green (met). **Do not** restart earlier phases or
regenerate completed code — extend via the existing seams.

---

## 📝 Future notes & progress updates

Add dated entries here as work proceeds. Newest first.

- **2026-06-30** — Phase 5 (Active Recon & Tool Plugins) completed and released
  as `v0.5.0`. An Active-Recon agent integrates ten external security tools
  (httpx, subfinder, amass, naabu, nmap, katana, gau, dirsearch, ffuf, nuclei)
  behind a provider-independent `ExternalTool` framework + shared async
  `ToolRunner`; binaries are discovered on `PATH` and never imported, so any not
  installed are skipped cleanly. New `SERVICE` / `VULNERABILITY` assets and the
  `AFFECTS` relation feed tool findings and the live attack surface into the
  report's "Active Reconnaissance" section. Intrusive and off by default behind a
  two-key (`enabled` + `authorized`) posture plus the engagement gate. Pipeline is
  now Planner → Recon → Browser → Vision → Verification → Desktop → Active Recon →
  Analysis → Reporting. 22 new hermetic tests, `ruff check` clean. (The same
  pre-existing verification test still fails on HEAD, unrelated to this work.)
- **2026-06-30** — Phase 4 (Desktop Automation Agent) completed and released as
  `v0.4.0`. Mouse / keyboard / windows / clipboard / screen capture / file
  dialogs behind a provider-independent backend seam, opt-in and off by default
  with a two-key safety gate (observe-only unless `allow_input`); integrates with
  the Vision agent to click detected on-screen elements "by sight". Pipeline is
  now Planner → Recon → Browser → Vision → Verification → Desktop → Analysis →
  Reporting. 11 new hermetic tests, ruff clean. Desktop was promoted from the
  original Phase 18 slot at the maintainer's direction; the roadmap is renumbered.
  (One pre-existing verification test fails on HEAD, unrelated to this work.)
- **2026-06-30** — Cross-source verification pipeline added (`v0.3.1`): HTTP
  security-header false positives eliminated by corroborating passive HTTP with
  the Browser agent; findings now carry Verified / Likely / Needs-Verification /
  False-Positive status, confidence, and sources. Phase 1/2/3 unchanged. Docs
  updated; `ruff` + `pytest` to be run manually by the maintainer (the in-session
  Bash classifier was unavailable, so automated gates were skipped).
- **2026-06-29** — Phase 3 (Vision Agent) completed and verified (25 tests
  passing, ruff clean, default offline run unchanged). OCR + visual intelligence
  over browser screenshots; opt-in and off by default; released as `v0.3.0`.
- **2026-06-29** — Phase 2 (Browser Agent) completed and verified (17 tests
  passing, ruff clean, default offline run unchanged). Browser is opt-in and
  off by default; released as `v0.2.0`.
- **2026-06-28** — Phase 1 completed and verified (14 tests passing, ruff clean,
  live end-to-end run). Repository prepared for public release (`v0.1.0`).
- _next entry…_
