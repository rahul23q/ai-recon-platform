# Roadmap

A phased plan to grow **recon-platform** from its Clean-Architecture foundation
into a full enterprise AI reconnaissance platform. Each phase builds on the
previous one **without rewriting existing layers** — new capabilities plug into
the established Protocol seams (agents, tools, renderers, bus, memory).

**Legend:** ✅ Completed · 🔜 Next · ⏳ Planned

| Phase | Milestone | Status |
|------:|-----------|:------:|
| 1 | Foundation | ✅ |
| 2 | Browser Agent | ✅ |
| 3 | Vision Agent | ✅ |
| 4 | Desktop Automation Agent | ✅ |
| 5 | Active Recon & Tool Plugins | ✅ |
| 6 | Network Agent | ✅ |
| 7 | API Discovery Agent | ✅ |
| 8 | JavaScript Analysis | ✅ |
| 9 | Authentication Workflows | 🔜 |
| 10 | Persistence & State | ⏳ |
| 11 | Vector Memory & Semantic Recall | ⏳ |
| 12 | Knowledge-Graph Agent & Visualization | ⏳ |
| 13 | Live Dashboard | ⏳ |
| 14 | Advanced Reporting & Standards Mapping | ⏳ |
| 15 | Analysis & Correlation Intelligence | ⏳ |
| 16 | Self-Reflection & Self-Healing | ⏳ |
| 17 | Human Interaction & Voice | ⏳ |
| 18 | Distributed Execution & Scaling | ⏳ |
| 19 | Threat Intelligence & Integrations | ⏳ |
| 20 | Hardening, Compliance & GA | ⏳ |

> **Reordering note.** Desktop automation was originally slotted at Phase 18; it
> was prioritized and delivered as **Phase 4** at the maintainer's direction, and
> the later phases were shifted down by one accordingly.

---

## Phase 1 — Foundation ✅

Clean-Architecture core (DI, config, logging, exceptions), domain Protocols and
entities, the A2A message bus, layered memory, the knowledge graph, passive
recon modules, the Planner/Recon/Analysis/Reporting agents, LangGraph
orchestration (with a sequential fallback), the plugin + MCP tool registries,
Markdown/HTML/JSON reporting, a FastAPI + WebSocket surface, and a Typer CLI.
**Outcome:** `recon passive-recon <target>` runs end-to-end, offline-capable.

## Phase 2 — Browser Agent ✅

A Playwright + Chrome DevTools Protocol agent for real-browser navigation and
DevTools/network inspection, wired behind the existing `Agent` Protocol and
orchestrator. Delivered headless Chromium browsing with retry + browser-restart
self-healing, page-state capture (network requests, response headers, cookies,
script inventory, same-origin DOM links), and screenshot evidence — opt-in and
off by default, degrading to a clean no-op when disabled or when Playwright is
absent. Form interaction and authentication flows build on this in Phase 8.

## Phase 3 — Vision Agent ✅

OCR + visual intelligence over the Browser agent's screenshots, wired behind the
existing `Agent` Protocol. Delivered a provider-independent OCR seam (EasyOCR /
RapidOCR / PaddleOCR + null fallback), a dependency-free heuristic element
detector and page classifier (login / admin / dashboard / Swagger / GraphQL /
CMS / error / payment / API-docs), on-screen text and entity extraction (emails,
phones, URLs, internal hosts, secrets), QR-code detection, new visual asset types
(`SCREENSHOT` / `VISUAL_ELEMENT` / `TEXT_REGION` / `QR_CODE`), screenshot-backed
findings, and a "Visual Intelligence" report section — opt-in and off by default,
degrading to a clean no-op without the `vision` extra. Click-by-sight and the
DOM → Vision → Human self-healing chain build on this perception layer in
Phase 15.

> **v0.3.1 — cross-source verification.** A Verification stage now sits between
> the Browser/Vision agents and Analysis (Planner → Recon → Browser → Vision →
> Verification → Analysis → Reporting). HTTP header analysis is case-insensitive
> and runs only on the final post-redirect response; findings are graded
> Verified / Likely / Needs-Verification / False-Positive with confidence and
> sources, eliminating the security-header false-positive class. A first step
> toward the broader correlation/verification work in Phase 14.

## Phase 4 — Desktop Automation Agent ✅

A Desktop agent controlling mouse, keyboard, window discovery/management,
clipboard, screen capture, and file-upload/download dialogs — for scenarios
beyond the browser, in strictly authorized contexts — wired behind the existing
`Agent` Protocol and orchestrator. Delivered a provider-independent input-backend
seam (`null` recorder + lazy `pyautogui` real-input backend), a `DesktopManager`
(windows / clipboard / capture) and a `DesktopSession`, with a **two-key safety
posture** (observe-only unless `allow_input`) so the default records *planned*
(dry-run) interactions without moving the real cursor. It reuses the Vision
agent's detected on-screen elements to click "by sight" — opt-in and off by
default, degrading to a clean no-op without the `desktop` extra (or a display).
The click-by-sight perception → action bridge feeds the self-healing chain in
Phase 16.

> Pipeline is now Planner → Recon → Browser → Vision → Verification → **Desktop**
> → Analysis → Reporting. Desktop was promoted from its original Phase 18 slot at
> the maintainer's direction; the later phases are renumbered below.

## Phase 5 — Active Recon & Tool Plugins ✅

External tool integrations as first-class plugins (httpx, subfinder, amass,
naabu, nmap, katana, gau, dirsearch, ffuf, nuclei), wired behind the existing
`Agent` Protocol and orchestrator. Delivered a provider-independent
`ExternalTool` framework with a shared async `ToolRunner` (timeout / retries /
cancellation / output capture) and a normalized `ToolExecution` record; binaries
are discovered on `PATH` and never imported, so any not installed are skipped
cleanly. Each tool normalizes its stdout into the common `Asset` / `Relation`
models (new `SERVICE` / `VULNERABILITY` assets and the `AFFECTS` relation),
feeding tool-reported vulnerabilities and the live attack surface into findings
and a new "Active Reconnaissance" report section. The active-recon workflow is
gated by a **two-key** posture (`enabled` + `authorized`) plus the engagement
authorization gate and `NETWORK_ACTIVE` / `SUBPROCESS` permissions — opt-in and
off by default, degrading to a clean skip when disabled, unauthorized, or with no
tool binaries present. Deeper request/response analysis builds on this in Phase 6.

> Pipeline is now Planner → Recon → Browser → Vision → Verification → Desktop →
> **Active Recon** → Analysis → Reporting.

## Phase 6 — Network Agent ✅

A **Network agent** performing deep analysis of already-captured request/response
data, wired behind the existing `Agent` Protocol and orchestrator. Delivered a
dependency-free detection layer (`network/detectors.py`: JWT decode/weakness
flagging, GraphQL/REST endpoint classification, WebSocket detection, CORS-hygiene
checks) and four `NetworkModule`s (`jwt_inspection`, `api_classification`,
`websocket_review`, `cors_hygiene`) that correlate the headers, cookies, tokens,
and endpoints already in the knowledge graph into new `JWT` / `API_ENDPOINT` /
`WEBSOCKET` assets (CORS issues merge onto the analyzed `HEADER`). Additive
analysis rules and a "Network Analysis" report section surface weak JWTs, insecure
CORS, exposed GraphQL/REST traffic, and unencrypted WebSockets. It is **passive**
(no new I/O) and opt-in, degrading to a clean no-op when disabled. The pipeline is
now Planner → Recon → Browser → Vision → Verification → Desktop → Active Recon →
**Network** → Analysis → Reporting. Deeper API characterization builds on this in
Phase 7.

> Pipeline is now Planner → Recon → Browser → Vision → Verification → Desktop →
> Active Recon → **Network** → Analysis → Reporting.

## Phase 7 — API Discovery Agent ✅

An **API-Discovery agent** that discovers and characterizes APIs across REST,
GraphQL, SOAP, and gRPC, wired behind the existing `Agent` Protocol and
orchestrator. Delivered a dependency-free detection layer
(`api_discovery/detectors.py`: API-style classification, REST resource/version
parsing, request-parameter extraction, auth-scheme detection, and OpenAPI/Swagger
parsing) and four `APIModule`s (`rest_inference`, `graphql_discovery`,
`soap_grpc_discovery`, `auth_scheme_detection`) that correlate the endpoints,
headers, JS files, and the Network agent's classified `API_ENDPOINT` assets
already in the graph into new `API` / `API_PARAMETER` / `AUTH_SCHEME` assets.
Additive analysis rules and an "API Discovery" report section surface the API
inventory, unauthenticated surface, and weak (Basic) auth. It is **passive** (no
new I/O) and opt-in, degrading to a clean no-op when disabled. The pipeline is now
Planner → Recon → Browser → Vision → Verification → Desktop → Active Recon →
Network → **API Discovery** → Analysis → Reporting. JavaScript-sourced endpoints
and secrets feed this surface further in Phase 8.

> Pipeline is now … → Active Recon → Network → **API Discovery** → Analysis →
> Reporting.

## Phase 8 — JavaScript Analysis ✅

A **JS-Analysis agent** that maps the client-side attack surface, wired behind the
existing `Agent` Protocol and orchestrator. Delivered a dependency-free analyzer
layer (`js_analysis/analyzers.py`: endpoint extraction, query-parameter
extraction, source-map discovery — with secret detection reusing the shared
patterns) and three `JSModule`s (`js_endpoints`, `js_secrets`, `js_source_maps`)
run over script bodies the agent **passively fetches** (GET-only, size-capped,
failure-tolerant — declaring `NETWORK_PASSIVE`, the same posture as passive
recon). Endpoints/secrets reuse the existing `ENDPOINT` / `SECRET` types (tagged
`via=js`) so they feed the Network and API-discovery agents and existing rules
unchanged; `SOURCE_MAP` is the one new type. Additive analysis rules (JS secrets,
source-map exposure, client-side surface) and a "JavaScript Analysis" report
section surface the findings. Opt-in and off by default, degrading to a clean
no-op when disabled or offline. The pipeline is now Planner → Recon → Browser →
Vision → Verification → Desktop → Active Recon → **JS Analysis** → Network → API
Discovery → Analysis → Reporting.

> Pipeline is now … → Active Recon → **JS Analysis** → Network → API Discovery →
> Analysis → Reporting (JS runs first so its endpoints feed traffic
> classification and API characterization).

## Phase 9 — Authentication Workflows ⏳

Login, registration, forgot-password, and admin-panel workflows with secure
credential handling. Captures authenticated sessions for downstream agents.

## Phase 10 — Persistence & State ⏳

Durable backends behind the existing Protocols: Redis (working memory + bus),
PostgreSQL (long-term store), SQLite (local), and full session history —
swappable via `bootstrap.py` with zero agent changes.

## Phase 11 — Vector Memory & Semantic Recall ⏳

Embeddings-backed semantic memory and retrieval-augmented recall over findings
and evidence, replacing the substring search in the in-memory store.

## Phase 12 — Knowledge-Graph Agent & Visualization ⏳

A dedicated Knowledge-Graph agent that continuously links domains, IPs,
certificates, endpoints, technologies, cookies, tokens, and secrets, plus an
interactive relationship-graph visualization.

## Phase 13 — Live Dashboard ⏳

A real-time web dashboard: agent thoughts, timeline, running tasks, network
requests, discovered endpoints, screenshots, evidence, console/errors, progress,
and resource usage — over the existing WebSocket event stream.

## Phase 14 — Advanced Reporting & Standards Mapping ⏳

PDF and DOCX renderers plus executive/technical templates, with OWASP, MITRE
ATT&CK, CWE, and CVSS mapping and a risk matrix.

## Phase 15 — Analysis & Correlation Intelligence ⏳

Smarter correlation: cross-source deduplication, severity ranking, exploitability
scoring, and LLM-suggested next actions and agent hand-offs.

## Phase 16 — Self-Reflection & Self-Healing ⏳

After-action reflection ("did this work? better approach? different tool?") and
recovery chains: browser restart + session recovery, OCR retry → DOM → Vision →
ask-human, with confidence-driven escalation.

## Phase 17 — Human Interaction & Voice ⏳

A Human-Interaction agent (ask → wait → continue) and a Voice agent for speech
recognition and synthesis, enabling conversational supervision.

## Phase 18 — Distributed Execution & Scaling ⏳

Celery workers, remote agents, Docker images, and Kubernetes manifests for
horizontal scaling and cloud deployment of the agent fleet.

## Phase 19 — Threat Intelligence & Integrations ⏳

Threat-intel enrichment (Shodan, VirusTotal, Censys, SecurityTrails) and outbound
integrations: Slack, Discord, Teams, email alerts, and SIEM forwarding.

## Phase 20 — Hardening, Compliance & GA ⏳

Security review of the platform itself, audit logging, multi-tenant isolation,
expanded test coverage, performance work, complete documentation, and a General
Availability release.

---

> This roadmap is a living document. Phases may be reordered or split as the
> project evolves; update statuses here and in [PROJECT_STATUS.md](PROJECT_STATUS.md)
> as milestones complete.
