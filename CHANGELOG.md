# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/).

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
