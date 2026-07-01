# Project Status

> A living record of what is built, what is in progress, and what comes next.
> Update this file whenever a milestone or notable feature lands.

| | |
|---|---|
| **Project** | recon-platform — AI-powered Web App Security Reconnaissance |
| **Current version** | `0.8.0` |
| **Current phase** | **Phase 8 — JavaScript Analysis ✅ Completed** |
| **Next milestone** | **Phase 9 — Authentication Workflows** |
| **Last updated** | 2026-07-01 |
| **Quality gates** | ✅ `ruff check` clean; `pytest` 117/118 (all 14 new JS-analysis tests green, plus the 17 API-discovery + 18 network tests). The same **pre-existing** verification test (`test_agreement_missing_reported_as_verified`) still fails on HEAD, unrelated to Phase 8 — see *Known issues* below. |

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

## ✅ Phase 6 — Network Agent (Completed)

Added a **Network agent** performing deep analysis of already-captured
request/response data, behind the existing `Agent` Protocol and orchestrator with
**zero rewrites** of earlier layers. Unlike active recon it is **entirely
passive** — it issues no new I/O, has no external dependency, and simply
correlates what earlier agents observed. Opt-in and off by default, degrading to a
clean no-op when disabled. The pipeline is now Planner → Recon → Browser → Vision
→ Verification → Desktop → Active Recon → **Network** → Analysis → Reporting.

### Implemented features

- **`network/` infrastructure** mirroring `recon/` / `vision/`: a dependency-free
  detection layer (`detectors.py`) carrying all the logic as pure, directly
  unit-testable functions — JWT decode (header+payload only; signatures are never
  verified) with weakness flagging (`alg=none`, symmetric alg, missing/past
  `exp`, sensitive claims), GraphQL/REST endpoint classification, `ws://`/`wss://`
  detection, and CORS-hygiene checks (wildcard/`null` origin, credentialed
  wildcard) — plus a `NetworkModule` base and a read-only `NetworkContext`
  snapshot.
- **Four network modules** + a `build_network_modules` factory (honouring the
  per-capability toggles): `jwt_inspection`, `api_classification`,
  `websocket_review`, and `cors_hygiene`. They read the headers, cookies, tokens
  (`SECRET`), and endpoints/URLs the earlier agents put in the graph and emit new
  `JWT` / `API_ENDPOINT` / `WEBSOCKET` assets with `CONTAINS` / `REFERENCES`
  relations; CORS issues merge onto the analyzed `HEADER` asset (no new asset type
  needed). Every module captures errors into `result.errors` and never raises.
- **`NetworkAgent`** snapshots the graph, runs the modules, merges results back,
  records a trace per module, and emits `network.*` A2A events for the dashboard.
- **Orchestration**: an independent `network` step (sequential + LangGraph node)
  after active recon and before analysis — the Planner's 3-task plan is untouched.
- **Analysis & reporting**: additive rules for weak JWTs, insecure CORS, exposed
  GraphQL endpoints, and unencrypted WebSockets, plus a network-traffic surface
  summary; a new "Network Analysis" report section (JWTs, CORS issues, API
  traffic, WebSocket endpoints).
- **Surfaces**: `NetworkPlugin` in the MCP catalogue (registered when enabled),
  `recon passive-recon --network`, `recon network <target>`, an API `network`
  flag, and `RECON_NETWORK__*` settings.
- **Quality**: 18 new hermetic network tests (no network, no external deps);
  `ruff check` clean; default offline run verified unchanged.

---

## ✅ Phase 7 — API Discovery Agent (Completed)

Added an **API-Discovery agent** that discovers and characterizes APIs across
REST, GraphQL, SOAP, and gRPC, behind the existing `Agent` Protocol and
orchestrator with **zero rewrites** of earlier layers. Like the Network agent it
is **entirely passive** — it issues no new I/O, has no external dependency, and
correlates what earlier agents observed. Opt-in and off by default, degrading to a
clean no-op when disabled. The pipeline is now Planner → Recon → Browser → Vision
→ Verification → Desktop → Active Recon → Network → **API Discovery** → Analysis →
Reporting.

### Implemented features

- **`api_discovery/` infrastructure** mirroring `network/`: a dependency-free
  detection layer (`detectors.py`) carrying all logic as pure, directly
  unit-testable functions — API-style classification (rest / graphql / soap /
  grpc), REST resource/version parsing, request-parameter extraction (query +
  identifier-style path segments), auth-scheme detection (Bearer / Basic / Digest
  / API-key / cookie), and OpenAPI/Swagger parsing — plus an `APIModule` base and
  a read-only `APIDiscoveryContext` snapshot.
- **Four API modules** + a `build_api_modules` factory (honouring the
  per-capability toggles): `rest_inference` (groups endpoints into REST APIs with
  resources/version + emits `API_PARAMETER` assets), `graphql_discovery` (uses the
  Network agent's classified `API_ENDPOINT` signal + path heuristics),
  `soap_grpc_discovery`, and `auth_scheme_detection`. They emit new `API` /
  `API_PARAMETER` / `AUTH_SCHEME` assets with `EXPOSES` relations. Every module
  captures errors into `result.errors` and never raises.
- **`APIDiscoveryAgent`** (role `API`) snapshots the graph, runs the modules,
  merges results back, records a trace per module, and emits `api.*` A2A events.
- **Orchestration**: an independent `api_discovery` step (sequential + LangGraph
  node) after network and before analysis — the Planner's 3-task plan is untouched.
- **Analysis & reporting**: additive rules for the API inventory, an
  unauthenticated-API-surface flag, and a weak-Basic-auth flag; a new "API
  Discovery" report section (APIs by style, auth schemes, parameters).
- **Surfaces**: `APIDiscoveryPlugin` in the MCP catalogue (registered when
  enabled), `recon passive-recon --api`, `recon api-discovery <target>`, an API
  `api` flag, and `RECON_API_DISCOVERY__*` settings.
- **Quality**: 17 new hermetic API-discovery tests (no network, no external deps);
  `ruff check` clean; default offline run verified unchanged.

---

## ✅ Phase 8 — JavaScript Analysis (Completed)

Added a **JS-Analysis agent** that maps the client-side attack surface, behind the
existing `Agent` Protocol and orchestrator with **zero rewrites** of earlier
layers. Unlike the Network / API-discovery correlators it performs *passive*
outbound fetches — GET-only retrieval of the scripts the target already serves
(declaring `NETWORK_PASSIVE`, the same posture as the passive-recon modules) —
then reasons over the text purely. Opt-in and off by default, degrading to a clean
no-op when disabled or offline. The pipeline is now Planner → Recon → Browser →
Vision → Verification → Desktop → Active Recon → **JS Analysis** → Network → API
Discovery → Analysis → Reporting.

### Implemented features

- **`js_analysis/` infrastructure**: a dependency-free analyzer layer
  (`analyzers.py`) carrying all logic as pure, directly unit-testable functions —
  endpoint extraction (absolute URLs + quoted paths, static assets filtered and
  resolved against the script URL), query-parameter extraction, source-map
  discovery, and an in-scope-host check — with secret detection reusing the shared
  `vision.detector.find_secrets` patterns so JS and OCR report secrets
  identically. Plus a `JSModule` base + `JSContext` (`{url: source}` snapshot) and
  a single, easily-mocked GET-only `fetch_js` seam.
- **Three JS modules** + a `build_js_modules` factory (honouring the
  per-capability toggles): `js_endpoints` (→ `ENDPOINT` + `API_PARAMETER`,
  tagged `via=js`), `js_secrets` (→ `SECRET`, tagged `via=js`), and
  `js_source_maps` (→ the new `SOURCE_MAP` type). Every module captures errors
  into `result.errors` and never raises.
- **`JSAnalysisAgent`** (role `JS_ANALYSIS`) gathers `JS_FILE` URLs from the
  graph, passively fetches them (capped by count/size, optional second-pass
  source-map fetch), runs the modules, merges results back, records a trace per
  module, and emits `js.*` A2A events.
- **Orchestration**: an independent `js_analysis` step (sequential + LangGraph
  node) after active recon and *before* network/API discovery, so JS-sourced
  endpoints feed traffic classification and API characterization — the Planner's
  3-task plan is untouched.
- **Analysis & reporting**: additive rules for secrets embedded in JS,
  source-map exposure, and a client-side-surface summary; a new "JavaScript
  Analysis" report section.
- **Surfaces**: `JSAnalysisPlugin` in the MCP catalogue (registered when
  enabled), `recon passive-recon --js`, `recon js-analysis <target>`, an API `js`
  flag, and `RECON_JS_ANALYSIS__*` settings.
- **Quality**: 14 new hermetic JS-analysis tests (fetch mocked; no real network);
  `ruff check` clean; default offline run verified unchanged.

---

## ⏭️ Next milestone — Phase 9: Authentication Workflows

Login, registration, forgot-password, and admin-panel workflows with secure
credential handling; capture authenticated sessions for downstream agents. See
[ROADMAP.md](ROADMAP.md) for the full phase plan.

**Entry criteria:** Phase 8 green (met). **Do not** restart earlier phases or
regenerate completed code — extend via the existing seams.

---

## 📝 Future notes & progress updates

Add dated entries here as work proceeds. Newest first.

- **2026-07-01** — Phase 8 (JavaScript Analysis) completed and released as
  `v0.8.0`. A JS-Analysis agent maps the client-side attack surface: it passively
  fetches (GET-only) the scripts the target serves and extracts endpoints,
  parameters, embedded secrets, and source-map references over a dependency-free
  analyzer layer and three modules, emitting `ENDPOINT`/`SECRET` assets tagged
  `via=js` plus a new `SOURCE_MAP` type. Additive analysis rules (JS secrets,
  source-map exposure, client-side surface) and a "JavaScript Analysis" report
  section surface the findings. It runs before the network/API agents so its
  endpoints feed their classification; pipeline is now … → Active Recon → JS
  Analysis → Network → API Discovery → Analysis → Reporting. 14 new hermetic tests
  (fetch mocked), `ruff check` clean. (The same pre-existing verification test
  still fails on HEAD, unrelated to this work.)
- **2026-07-01** — Phase 7 (API Discovery Agent) completed and released as
  `v0.7.0`. A passive API-Discovery agent characterizes APIs across REST, GraphQL,
  SOAP, and gRPC — REST resource/version inference with parameter extraction,
  GraphQL discovery (reusing the Network agent's classified traffic), SOAP/gRPC
  detection, and auth-scheme detection — over a dependency-free detection layer and
  four modules, emitting new `API` / `API_PARAMETER` / `AUTH_SCHEME` assets.
  Additive analysis rules (API inventory, unauthenticated surface, weak Basic auth)
  and an "API Discovery" report section surface the findings. Passive (no new I/O)
  and off by default; pipeline is now … → Active Recon → Network → API Discovery →
  Analysis → Reporting. 17 new hermetic tests, `ruff check` clean. (The same
  pre-existing verification test still fails on HEAD, unrelated to this work.)
- **2026-07-01** — Phase 6 (Network Agent) completed and released as `v0.6.0`. A
  passive Network agent correlates already-captured request/response data — JWT
  inspection (unsigned/symmetric/expired/sensitive-claim flags), CORS hygiene
  (wildcard / credentialed-wildcard / null origin), GraphQL/REST traffic
  classification, and WebSocket review — over a dependency-free detection layer and
  four modules, emitting new `JWT` / `API_ENDPOINT` / `WEBSOCKET` assets (CORS
  issues merge onto the analyzed `HEADER`). Additive analysis rules and a "Network
  Analysis" report section surface the findings. Passive (no new I/O) and off by
  default; pipeline is now Planner → Recon → Browser → Vision → Verification →
  Desktop → Active Recon → Network → Analysis → Reporting. 18 new hermetic tests,
  `ruff check` clean. (The same pre-existing verification test still fails on HEAD,
  unrelated to this work.)
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
