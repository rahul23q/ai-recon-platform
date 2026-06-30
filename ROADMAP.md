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
| 5 | Active Recon & Tool Plugins | 🔜 |
| 6 | Network Agent | ⏳ |
| 7 | API Discovery Agent | ⏳ |
| 8 | JavaScript Analysis | ⏳ |
| 9 | Authentication Workflows | ⏳ |
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

## Phase 5 — Active Recon & Tool Plugins 🔜

External tool integrations as first-class plugins (httpx, subfinder, naabu,
katana, gau, amass, dirsearch, ffuf, nuclei, nmap). Adds the active-recon
workflow gated by explicit authorization and `NETWORK_ACTIVE` permissions.

## Phase 6 — Network Agent ⏳

Deep analysis of requests/responses: header hygiene, JWT inspection, GraphQL and
REST traffic, and WebSocket message review. Correlates network observations into
findings.

## Phase 7 — API Discovery Agent ⏳

Discover and characterize APIs across REST, SOAP, GraphQL, and gRPC — schema
inference, endpoint enumeration, and auth-scheme detection.

## Phase 8 — JavaScript Analysis ⏳

Extract endpoints, parameters, and potential secrets from JavaScript bundles and
source maps; map the client-side attack surface and feed it into the graph.

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
