# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/).

## [0.9.0] — 2026-07-02

### Phase 9 — Authentication Workflows (Completed)

An **Authentication agent** that drives login, registration, forgot-password, and
admin-panel workflows and captures authenticated sessions, wired behind the
existing `Agent` Protocol and orchestrator without rewriting any earlier layer.
Authenticating is **active/intrusive** (it submits credentials), so — like active
recon — it sits behind a *two-key* posture (`enabled` + `authorized`) plus the
engagement authorization gate. Opt-in and off by default, degrading to a clean
no-op when disabled, unauthorized, or with no browser backend. The pipeline is now
Planner → Recon → Browser → Vision → Verification → Desktop → Active Recon →
**Authentication** → JS Analysis → Network → API Discovery → Analysis → Reporting.

#### Added

- **Auth infrastructure** (`auth/`) with a Playwright-free, hermetically-testable
  core: pure form heuristics (`forms.py` — field classification,
  username/email/password/submit location, login-success detection),
  candidate-URL discovery from the graph (`discovery.py`), `SecretStr`-backed
  credential handling with masking (`credentials.py`), value objects (`models.py`
  — `AuthResult` / `CapturedSession`), and a narrow `AuthPage` **protocol seam**
  (`page.py`) with a Playwright-backed adapter + an `open_auth_page` factory the
  agent and tests drive.
- **Four workflows** + a `build_workflows` factory (per-workflow toggles):
  `login`, `registration`, `forgot_password`, and `admin_probe`. They call only
  the `AuthPage` seam and the pure heuristics — identical against the real browser
  and the test fake — and every page interaction is failure-wrapped.
- **`AuthenticationAgent`** (role `AUTHENTICATION`): two-key + gate skip; discovers
  candidate URLs, opens the browser via the seam, runs the workflows, and captures
  each session to **episodic memory** (cookie values, for downstream reuse) plus a
  masked **`SESSION`** asset (cookie names only). Credentials are masked in traces
  and never written to the graph or report.
- **Orchestration**: an independent `authentication` step (sequential + LangGraph
  node) after active recon and before JS analysis — the Planner's 3-task plan is
  untouched.
- **Analysis & reporting**: additive rules for admin panels reachable without
  authentication (HIGH), credentials submitted over cleartext HTTP (HIGH), and a
  workflow summary; a new "Authentication" report section (outcomes + cookie names
  only, with an explicit "credentials never shown" note).
- **Surfaces**: `AuthenticationPlugin` in the MCP catalogue (descriptor-only — the
  real flow needs the live agent), `recon passive-recon --auth`, `recon auth
  <target>`, an API `auth` flag, and `RECON_AUTH__*` settings.
- **New domain types**: `AssetType.SESSION` and `AgentRole.AUTHENTICATION`
  (`WorkflowType.AUTH` already existed).

#### Security

- Credentials are read from the environment as `SecretStr`, masked in every trace
  and finding, and never persisted to the graph or rendered in reports; captured
  cookie **values** live only in episodic memory (the graph/report carry cookie
  **names** only). A test asserts credentials never appear in the rendered report.

#### Quality

- 12 new hermetic tests (`tests/test_auth.py`): form/discovery/credential unit
  tests, workflow tests over a scripted `FakeAuthPage`, the two-key gate, and a
  stubbed end-to-end run (with `open_auth_page` monkeypatched).
- `ruff check` clean. The pre-existing `test_agreement_missing_reported_as_verified`
  failure on HEAD is unrelated to this work (see PROJECT_STATUS.md → Known issues).

## [0.8.0] — 2026-07-01

### Phase 8 — JavaScript Analysis (Completed)

A **JS-Analysis agent** that maps the client-side attack surface, wired behind the
existing `Agent` Protocol and orchestrator without rewriting any earlier layer.
Unlike the Network / API-discovery correlators it performs *passive* outbound
fetches — GET-only retrieval of the scripts the target already serves (declaring
`NETWORK_PASSIVE`, the same posture as the passive-recon modules) — then reasons
over the text purely. Opt-in and off by default, degrading to a clean no-op when
disabled or offline. The pipeline is now Planner → Recon → Browser → Vision →
Verification → Desktop → Active Recon → **JS Analysis** → Network → API Discovery
→ Analysis → Reporting.

#### Added

- **JS-analysis infrastructure** (`js_analysis/`): a dependency-free analyzer layer
  (`analyzers.py`) carrying all logic as pure, directly unit-testable functions —
  endpoint extraction (absolute URLs + quoted paths, static assets filtered,
  resolved against the script URL), query-parameter extraction, source-map
  discovery, and an in-scope-host check — with secret detection reusing the shared
  `vision.detector.find_secrets` patterns. Plus a `JSModule` base + `JSContext`
  (`{url: source}` snapshot) and a single, easily-mocked GET-only `fetch_js` seam
  (size-capped, failure-tolerant — returns `None` instead of raising).
- **Three JS modules** + a `build_js_modules` factory (honouring per-capability
  toggles): `js_endpoints` (→ `ENDPOINT` + `API_PARAMETER`, tagged `via=js`, with
  `REFERENCES` relations back to the `JS_FILE`), `js_secrets` (→ `SECRET`, tagged
  `via=js`, `CONTAINS` relation), and `js_source_maps` (→ the new `SOURCE_MAP`
  type). Modules are defensive — errors are captured in `result.errors`, never
  raised.
- **`JSAnalysisAgent`** (role `JS_ANALYSIS`) that gathers `JS_FILE` URLs from the
  graph, passively fetches them (capped by count/size, optional second-pass
  source-map fetch), runs the modules, merges results back, records a reasoning
  trace per module, and emits `js.*` A2A events.
- **Orchestration**: an independent `js_analysis` step (sequential + LangGraph
  node) after active recon and *before* network/API discovery — so JS-sourced
  endpoints feed traffic classification and API characterization. The Planner's
  3-task plan is untouched.
- **Analysis & reporting**: additive rules for secrets embedded in JS, source-map
  exposure, and a client-side-surface summary; a new "JavaScript Analysis" report
  section.
- **Surfaces**: `JSAnalysisPlugin` in the MCP catalogue (registered when enabled),
  `recon passive-recon --js`, `recon js-analysis <target>`, an API `js` flag, and
  `RECON_JS_ANALYSIS__*` settings.
- **New domain types**: `AssetType.SOURCE_MAP` and `AgentRole.JS_ANALYSIS`
  (`WorkflowType.JS_ANALYSIS` already existed).

#### Quality

- 14 new hermetic tests (`tests/test_js_analysis.py`): analyzer unit tests, module
  tests over a hand-built context, and a stubbed end-to-end run (with `fetch_js`
  monkeypatched) proving JS assets reach the graph, become findings, and render a
  report section.
- `ruff check` clean. The pre-existing `test_agreement_missing_reported_as_verified`
  failure on HEAD is unrelated to this work (see PROJECT_STATUS.md → Known issues).

## [0.7.0] — 2026-07-01

### Phase 7 — API Discovery Agent (Completed)

An **API-Discovery agent** that discovers and characterizes APIs across REST,
GraphQL, SOAP, and gRPC, wired behind the existing `Agent` Protocol and
orchestrator without rewriting any earlier layer. Like the Network agent it is
**entirely passive** — it issues no new I/O and has no external dependency; it
simply correlates what earlier agents observed. Opt-in and off by default,
degrading to a clean no-op when disabled. The pipeline is now Planner → Recon →
Browser → Vision → Verification → Desktop → Active Recon → Network → **API
Discovery** → Analysis → Reporting.

#### Added

- **API-discovery infrastructure** (`api_discovery/`): a dependency-free detection
  layer (`detectors.py`) carrying all logic as pure, directly unit-testable
  functions — API-style classification (rest / graphql / soap / grpc), REST
  resource/version parsing, request-parameter extraction (query + identifier-style
  path segments), auth-scheme detection (Bearer / Basic / Digest / API-key /
  cookie), and OpenAPI/Swagger parsing — plus an `APIModule` base and a read-only
  `APIDiscoveryContext` snapshot.
- **Four API modules** + a `build_api_modules` factory (honouring the
  per-capability toggles): `rest_inference` (groups endpoint URLs into REST APIs
  with base path / version / resources and emits `API_PARAMETER` assets),
  `graphql_discovery` (reuses the Network agent's classified `API_ENDPOINT` signal
  plus path heuristics), `soap_grpc_discovery`, and `auth_scheme_detection`. They
  emit new `API` / `API_PARAMETER` / `AUTH_SCHEME` assets with `EXPOSES`
  relations. Modules are defensive — errors are captured in `result.errors`, never
  raised.
- **`APIDiscoveryAgent`** (role `API`) that snapshots the graph, runs the modules,
  merges results back, records a reasoning trace per module, and emits `api.*` A2A
  events.
- **Orchestration**: an independent `api_discovery` step (sequential + LangGraph
  node) after network and before analysis — the Planner's 3-task plan is untouched.
- **Analysis & reporting**: additive rules for the API inventory, an
  unauthenticated-API-surface flag, and a weak-Basic-auth flag; a new "API
  Discovery" report section (APIs by style, auth schemes, parameters).
- **Surfaces**: `APIDiscoveryPlugin` in the MCP catalogue (registered when
  enabled), `recon passive-recon --api`, `recon api-discovery <target>`, an API
  `api` flag, and `RECON_API_DISCOVERY__*` settings.
- **New domain types**: `AssetType.API` / `API_PARAMETER` / `AUTH_SCHEME` (the
  `AgentRole.API` role and `WorkflowType.API_DISCOVERY` already existed).

#### Quality

- 17 new hermetic tests (`tests/test_api_discovery.py`): detector unit tests,
  module tests over a hand-built context, and a stubbed end-to-end run proving API
  assets reach the graph, become findings, and render a report section.
- `ruff check` clean. The pre-existing `test_agreement_missing_reported_as_verified`
  failure on HEAD is unrelated to this work (see PROJECT_STATUS.md → Known issues).

## [0.6.0] — 2026-07-01

### Phase 6 — Network Agent (Completed)

A **Network agent** that performs deep analysis of already-captured
request/response data, wired behind the existing `Agent` Protocol and orchestrator
without rewriting any earlier layer. Unlike active recon it is **entirely
passive** — it issues no new I/O and has no external dependency; it simply
correlates what earlier agents observed. Opt-in and off by default, degrading to a
clean no-op when disabled. The pipeline is now Planner → Recon → Browser → Vision
→ Verification → Desktop → Active Recon → **Network** → Analysis → Reporting.

#### Added

- **Network infrastructure** (`network/`): a dependency-free detection layer
  (`detectors.py`) carrying all logic as pure, directly unit-testable functions —
  JWT decode (header+payload only; **signatures are never verified**) with
  weakness flagging (`alg=none`, symmetric algorithms, missing/past `exp`,
  sensitive claims), GraphQL/REST endpoint classification, `ws://`/`wss://`
  detection, and CORS-hygiene checks (wildcard / `null` origin, and the
  exploitable credentialed-wildcard case) — plus a `NetworkModule` base and a
  read-only `NetworkContext` snapshot.
- **Four network modules** + a `build_network_modules` factory (honouring the
  per-capability toggles): `jwt_inspection`, `api_classification`,
  `websocket_review`, and `cors_hygiene`. They read the headers, cookies, tokens
  (`SECRET`), and endpoints/URLs already in the knowledge graph and emit new
  `JWT` / `API_ENDPOINT` / `WEBSOCKET` assets with `CONTAINS` / `REFERENCES`
  relations; CORS issues merge onto the analyzed `HEADER` asset (no new asset type
  needed). Modules are defensive — errors are captured in `result.errors`, never
  raised.
- **`NetworkAgent`** that snapshots the graph, runs the modules, merges results
  back, records a reasoning trace per module, and emits `network.*` A2A events.
- **Orchestration**: an independent `network` step (sequential + LangGraph node)
  after active recon and before analysis — the Planner's 3-task plan is untouched.
- **Analysis & reporting**: additive rules for weak JWTs, insecure CORS, exposed
  GraphQL endpoints, and unencrypted WebSockets, plus a network-traffic surface
  summary; a new "Network Analysis" report section.
- **Surfaces**: `NetworkPlugin` in the MCP catalogue (registered when enabled),
  `recon passive-recon --network`, `recon network <target>`, an API `network`
  flag, and `RECON_NETWORK__*` settings.
- **New domain types**: `AssetType.JWT` / `WEBSOCKET` / `API_ENDPOINT` and
  `AgentRole.NETWORK`.

#### Quality

- 18 new hermetic tests (`tests/test_network.py`): detector unit tests, module
  tests over a hand-built context, and a stubbed end-to-end run proving network
  assets reach the graph, become findings, and render a report section.
- `ruff check` clean. The pre-existing `test_agreement_missing_reported_as_verified`
  failure on HEAD is unrelated to this work (see PROJECT_STATUS.md → Known issues).

## [0.5.0] — 2026-06-30

### Phase 5 — Active Recon & Tool Plugins (Completed)

An **Active-Recon agent** that integrates ten best-of-breed external security
tools (httpx, subfinder, amass, naabu, nmap, katana, gau, dirsearch, ffuf,
nuclei) as first-class plugins, wired behind the existing `Agent` Protocol and
orchestrator without rewriting any earlier layer. Opt-in and off by default,
behind a *two-key* authorization posture, and **intrusive** by nature
(`NETWORK_ACTIVE` + `SUBPROCESS`). The pipeline is now Planner → Recon → Browser
→ Vision → Verification → Desktop → **Active Recon** → Analysis → Reporting.

#### Added

- **Active-recon infrastructure** (`active_recon/`): a provider-independent
  external-tool framework mirroring `recon/` / `desktop/`. An `ExternalTool`
  contract (declare a binary, build a command line, parse stdout into the common
  `Asset` / `Relation` domain models), a shared async `ToolRunner` (one place for
  timeout / retries / cancellation / output-capture, killing the child on expiry
  or abort), a normalized `ToolExecution` record (command / stdout / stderr /
  exit / duration / timed-out / skipped), and an import-free `binary_available`
  PATH probe. Tools are discovered on `PATH` and **never imported**, so a missing
  binary is skipped cleanly and the platform installs and runs without any present.
- **Ten tool wrappers** + a `build_active_tools` factory and `ACTIVE_TOOLS` map:
  httpx (live HTTP probe → `URL` / `TECHNOLOGY`), subfinder & amass (passive
  subdomains → `SUBDOMAIN` + `SUBDOMAIN_OF`), naabu (ports → `PORT` + `EXPOSES`),
  nmap (grepable service/version → `SERVICE` + `EXPOSES`), katana / gau /
  dirsearch / ffuf (crawl/fuzz → `ENDPOINT` / `URL`), and nuclei (templated
  findings → `VULNERABILITY` with severity + `AFFECTS`). Parsers are defensive —
  unknown keys, blank lines, and partial output are ignored, never raised.
- **Two-key safety posture**: `RECON_ACTIVE_RECON__ENABLED` turns the agent on;
  `RECON_ACTIVE_RECON__AUTHORIZED` is a separate explicit acknowledgment that the
  operator is permitted to actively scan. Tools run only when **both** are true
  **and** the target passes the engagement authorization gate; any other state
  records a clean skip trace and returns empty — nothing intrusive by accident.
- **Asset / relation types**: `SERVICE` and `VULNERABILITY` assets (severity in
  `attributes`) and the `AFFECTS` relation (a vulnerability affects an asset).
- **`ActiveReconAgent`**: builds the configured tool set (all by default, or a
  named subset), runs each through the shared runner, merges results into the
  knowledge graph, records a reasoning trace per tool, stores each full execution
  in episodic memory, and emits `active.*` A2A events for the dashboard.
- **Orchestration**: an independent `active_recon` step (sequential + LangGraph
  node) between desktop and analysis — the Planner's 3-task plan is untouched.
- **Analysis & reporting**: additive rules turning tool-reported vulnerabilities
  into ranked findings and summarizing the discovered live attack surface, plus
  an "Active Reconnaissance" report section (open services + reported
  vulnerabilities grouped by severity).
- **Surfaces**: `ActiveReconPlugin` exposing each tool in the MCP catalogue
  (registered only when enabled), `recon passive-recon --active`, a dedicated
  `recon active-recon <target>` command, an API `active` flag, and
  `RECON_ACTIVE_RECON__*` settings.
- **Quality**: 22 new hermetic tests (no real binaries / subprocess / network) —
  the ten parsers, the framework (`ToolExecution`, runner skip/parse paths,
  plugin adapter), and the two-key gate + a stubbed end-to-end run; `ruff check`
  clean; default offline run verified unchanged.

#### Known issues

- `tests/test_verification.py::test_agreement_missing_reported_as_verified` fails
  on `main` and is **pre-existing and unrelated to Phase 5** (it fails identically
  with all Phase-5 changes stashed; Phase 5 touches none of the verification
  path). Root cause is a Phase-1 ↔ Phase-3.1 interaction: the knowledge graph
  dedupes `HEADER` assets by `type:value`, so identical headers emitted by both
  the passive (`http_headers`) and browser (`network_capture`) sources collapse
  into one asset keeping a single `source`. `collect_header_maps` then sees an
  empty browser map, `browser_observed` becomes `False`, and CSP is graded
  `LIKELY`-missing instead of `VERIFIED`-missing, so no "verified missing" finding
  is produced. A correct fix requires the central graph merge to preserve multiple
  observation sources for an identical-value asset — a core change that warrants
  its own reviewed work (deferred; tracked with the Phase 15 correlation work).
  See *Known issues* in [PROJECT_STATUS.md](PROJECT_STATUS.md) for detail.

## [0.4.0] — 2026-06-30

### Phase 4 — Desktop Automation Agent (Completed)

A **Desktop agent** for OS automation (mouse, keyboard, windows, clipboard,
screen capture, and file-upload/download dialogs), wired behind the existing
`Agent` Protocol and orchestrator without rewriting any earlier layer. Opt-in and
off by default; behind a *two-key* safety posture and degrading to a clean no-op
when disabled or when no desktop backend is installed. The pipeline is now
Planner → Recon → Browser → Vision → Verification → **Desktop** → Analysis →
Reporting.

#### Added

- **Desktop infrastructure** (`desktop/`): provider-independent `DesktopBackend`
  (a `null` recorder that is always available + a lazy `pyautogui` real-input
  backend, with a name-based factory that falls back to `null`), a
  `DesktopManager` (window discovery/management via `pygetwindow`, clipboard via
  `pyperclip` with an in-process buffer fallback, and screen capture via
  pyautogui / `mss` / Pillow), and a `DesktopSession` action lifecycle wrapper
  that records every interaction and enforces the input safety gate.
- **Two-key safety posture**: `RECON_DESKTOP__ENABLED` turns on read-only
  observation (windows, screen capture, clipboard read); synthetic mouse/keyboard
  input additionally requires `RECON_DESKTOP__ALLOW_INPUT`. In the default
  (input-disabled) mode, interactions are recorded as **planned (dry-run)**
  `DESKTOP_ACTION` assets so a run is fully auditable without ever moving the
  real cursor.
- **Desktop modules**: `window_discovery` (→ `WINDOW`), `screen_capture` (→
  `SCREENSHOT` tagged `via=desktop`), `clipboard` (→ `DESKTOP_ACTION`), and
  `ui_interaction` — which **reuses the Vision agent's detected on-screen
  elements** (`VISUAL_ELEMENT` bounding boxes) to click "by sight", linking each
  action back to the element it acted on.
- **Asset types**: `WINDOW` and `DESKTOP_ACTION` (its concrete kind —
  mouse_move / click / type / hotkey / clipboard / screen_capture / file_dialog —
  in `attributes["action_type"]`); `AgentRole.DESKTOP`; `ToolPermission.DESKTOP`.
- **`DesktopAgent`**: gathers Vision elements from the graph, drives the session,
  populates the graph, records a trace per module, and emits `desktop.started` /
  `desktop.window` / `desktop.capture` / `desktop.clipboard` / `desktop.action` /
  `desktop.completed` A2A events.
- **Orchestration**: an independent `desktop` step between verification and
  analysis (sequential path + LangGraph node) that runs only when enabled; the
  Planner's 3-task plan is untouched.
- **Analysis & reporting**: an additive desktop-automation summary finding
  (windows observed + interactions, flagging any real input) and a **Desktop
  Automation** report section.
- **Tooling & surfaces**: `DesktopPlugin` (`plugins/desktop.py`) exposes the
  desktop modules in the MCP catalogue when enabled; `recon passive-recon
  --desktop` and a new `recon desktop <target>` command; a `desktop` flag on the
  API `RunRequest`; `RECON_DESKTOP__*` settings; a `desktop` install extra.
- **Tests** (`tests/test_desktop.py`): hermetic — no real mouse/keyboard/screen,
  no GUI libraries. Backend factory fallback, the input safety gate (no synthetic
  input when `allow_input=False`, input sent when true), clipboard buffer
  fallback, element-centre maths, and the disabled-by-default / enabled-stubbed /
  graceful-degradation pipeline cases (11 tests).

#### Unchanged

- Phase 1 / 2 / 3 (+ verification) functionality is intact; all prior tests
  behave as before. The Browser / Vision / Verification agents are unmodified —
  the desktop stage only *reads* their assets (Vision elements) and adds its own.

> **Roadmap note.** Desktop automation (originally sketched as Phase 18) was
> prioritized and delivered here as Phase 4 at the maintainer's direction; the
> roadmap has been renumbered accordingly.

[0.4.0]: https://github.com/OWNER/recon-platform/releases/tag/v0.4.0

## [0.3.1] — 2026-06-30

### Cross-source verification pipeline (HTTP security-header false positives)

Eliminates a class of false positives in HTTP security-header detection (e.g.
**Content-Security-Policy** reported missing when the server only sends it to
real browsers) by corroborating passive observations against the Browser agent
before they become findings. The pipeline is now Planner → Recon → Browser →
Vision → **Verification** → Analysis → Reporting. No existing layer was rewritten.

#### Added

- **Verification stage** (`verification/headers.py` + `agents/verification.py`):
  a new `VerificationAgent` that runs before analysis and cross-checks required
  security headers across sources. Pure, import-light comparison logic with a
  clear verdict matrix.
- **`VerificationStatus`** enum (`verified` / `likely` / `needs_verification` /
  `false_positive`) and a `Verification` domain model; `Finding` now carries
  `verification_status` and `verification_sources` (every finding declares its
  status, confidence score, and sources — e.g. `passive-http`, `browser`).
- **Report sections**: findings are grouped into **Verified Findings**, **Likely
  Findings**, **Needs Manual Verification**, and **False Positives**, each finding
  showing its verification status, confidence, and sources.
- **Tests** (`tests/test_verification.py`): header case-insensitivity, final-
  response-after-redirect analysis, passive/browser agreement and disagreement,
  and false-positive detection.

#### Changed

- **HTTP header analysis** (`recon.modules.HTTPHeadersModule`): header names are
  normalized to lowercase (RFC 9110 case-insensitivity), analysis is performed
  only on the **final** response after following redirects (the redirect chain
  and final status are recorded), and both presence and value are stored.
- **Analysis** (`AnalysisAgent.analyze`): consumes verification verdicts and
  splits security-header results into verified / likely / needs-verification /
  false-positive findings instead of a single unconditional "missing" finding;
  all findings are stamped with their originating sources.

#### Unchanged

- Phase 1 / 2 / 3 functionality is intact; all prior tests pass. Browser and
  Vision agents are unmodified (the verification stage only *reads* their assets).

[0.3.1]: https://github.com/OWNER/recon-platform/releases/tag/v0.3.1

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
