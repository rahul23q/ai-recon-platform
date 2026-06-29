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
| 3 | Vision Agent | 🔜 |
| 4 | Active Recon & Tool Plugins | ⏳ |
| 5 | Network Agent | ⏳ |
| 6 | API Discovery Agent | ⏳ |
| 7 | JavaScript Analysis | ⏳ |
| 8 | Authentication Workflows | ⏳ |
| 9 | Persistence & State | ⏳ |
| 10 | Vector Memory & Semantic Recall | ⏳ |
| 11 | Knowledge-Graph Agent & Visualization | ⏳ |
| 12 | Live Dashboard | ⏳ |
| 13 | Advanced Reporting & Standards Mapping | ⏳ |
| 14 | Analysis & Correlation Intelligence | ⏳ |
| 15 | Self-Reflection & Self-Healing | ⏳ |
| 16 | Human Interaction & Voice | ⏳ |
| 17 | Distributed Execution & Scaling | ⏳ |
| 18 | Desktop Agent & OS Automation | ⏳ |
| 19 | Threat Intelligence & Integrations | ⏳ |
| 20 | Hardening, Compliance & GA | ⏳ |

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

## Phase 3 — Vision Agent 🔜

OpenCV + EasyOCR for screen understanding: read UI text, detect elements, and
click by sight when the DOM is unreliable. Establishes the perception layer used
by self-healing (DOM → Vision → Human escalation).

## Phase 4 — Active Recon & Tool Plugins ⏳

External tool integrations as first-class plugins (httpx, subfinder, naabu,
katana, gau, amass, dirsearch, ffuf, nuclei, nmap). Adds the active-recon
workflow gated by explicit authorization and `NETWORK_ACTIVE` permissions.

## Phase 5 — Network Agent ⏳

Deep analysis of requests/responses: header hygiene, JWT inspection, GraphQL and
REST traffic, and WebSocket message review. Correlates network observations into
findings.

## Phase 6 — API Discovery Agent ⏳

Discover and characterize APIs across REST, SOAP, GraphQL, and gRPC — schema
inference, endpoint enumeration, and auth-scheme detection.

## Phase 7 — JavaScript Analysis ⏳

Extract endpoints, parameters, and potential secrets from JavaScript bundles and
source maps; map the client-side attack surface and feed it into the graph.

## Phase 8 — Authentication Workflows ⏳

Login, registration, forgot-password, and admin-panel workflows with secure
credential handling. Captures authenticated sessions for downstream agents.

## Phase 9 — Persistence & State ⏳

Durable backends behind the existing Protocols: Redis (working memory + bus),
PostgreSQL (long-term store), SQLite (local), and full session history —
swappable via `bootstrap.py` with zero agent changes.

## Phase 10 — Vector Memory & Semantic Recall ⏳

Embeddings-backed semantic memory and retrieval-augmented recall over findings
and evidence, replacing the substring search in the in-memory store.

## Phase 11 — Knowledge-Graph Agent & Visualization ⏳

A dedicated Knowledge-Graph agent that continuously links domains, IPs,
certificates, endpoints, technologies, cookies, tokens, and secrets, plus an
interactive relationship-graph visualization.

## Phase 12 — Live Dashboard ⏳

A real-time web dashboard: agent thoughts, timeline, running tasks, network
requests, discovered endpoints, screenshots, evidence, console/errors, progress,
and resource usage — over the existing WebSocket event stream.

## Phase 13 — Advanced Reporting & Standards Mapping ⏳

PDF and DOCX renderers plus executive/technical templates, with OWASP, MITRE
ATT&CK, CWE, and CVSS mapping and a risk matrix.

## Phase 14 — Analysis & Correlation Intelligence ⏳

Smarter correlation: cross-source deduplication, severity ranking, exploitability
scoring, and LLM-suggested next actions and agent hand-offs.

## Phase 15 — Self-Reflection & Self-Healing ⏳

After-action reflection ("did this work? better approach? different tool?") and
recovery chains: browser restart + session recovery, OCR retry → DOM → Vision →
ask-human, with confidence-driven escalation.

## Phase 16 — Human Interaction & Voice ⏳

A Human-Interaction agent (ask → wait → continue) and a Voice agent for speech
recognition and synthesis, enabling conversational supervision.

## Phase 17 — Distributed Execution & Scaling ⏳

Celery workers, remote agents, Docker images, and Kubernetes manifests for
horizontal scaling and cloud deployment of the agent fleet.

## Phase 18 — Desktop Agent & OS Automation ⏳

A Desktop agent controlling mouse, keyboard, clipboard, windows, and
applications for scenarios beyond the browser (strictly authorized contexts).

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
