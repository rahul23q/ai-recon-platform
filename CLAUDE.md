# CLAUDE.md — Operating Guide for AI Coding Sessions

> This file is the durable contract for any AI assistant (Claude or otherwise)
> working in this repository. Read it **in full** at the start of every session,
> before writing or changing any code.

---

## 1. What this project is

**recon-platform** is an **enterprise-grade, AI-powered Web Application Security
Reconnaissance Platform** for **authorized security testing**. It is designed to
behave like an autonomous security consultant that can plan, reason, browse,
observe, remember, use tools, ask for help, learn from previous actions, and
generate professional reports.

It is **not** a script. It is a modular, production-oriented agent platform built
to grow into a large system (many agents, MCP tools, plugins, a live dashboard,
distributed workers) **without rewriting existing layers**.

> ⚠️ **Authorized use only.** Every capability must respect the authorization
> gate and the passive-by-default posture. Never add features whose primary
> purpose is evasion, mass targeting, or unauthorized access. See
> [SECURITY.md](SECURITY.md).

---

## 2. Architecture (preserve this)

The codebase follows **Clean Architecture** with strict inward-pointing
dependencies and **SOLID** principles. Layers, outermost depending on innermost:

```
domain/            Entities + Protocol interfaces (NO framework deps)
   ▲
core/              Config (pydantic-settings), DI container, logging, exceptions
   ▲
infrastructure     llm/  a2a/  memory/  knowledge_graph/  recon/  plugins/  mcp/
   ▲
agents/            Planner · Recon · Analysis · Reporting (+ base reasoning loop)
   ▲
orchestration/     LangGraph state machine (+ sequential fallback)
api/  cli/         FastAPI + WebSocket · Typer
```

**The Dependency Rule:** `domain/` defines `Protocol` contracts; everything else
depends on those abstractions, never on concretions. Concrete implementations
are bound to their Protocols in exactly **one** place: `bootstrap.py` (the
composition root). Agents and orchestration receive dependencies by injection.

**Key contracts** live in `domain/interfaces.py`: `MessageBus`, `LLMProvider`,
`Memory`, `KnowledgeGraph`, `Tool`, `ToolRegistry`, `Plugin`, `Agent`,
`ReportRenderer`, `Orchestrator`, `Planner`.

**Reasoning model:** every agent action records a `ReasoningTrace`
(Thought → Observation → Reason → Plan → Action → Result → Reflection →
Next Action → Confidence → Recovery Plan).

**Messaging:** agents communicate via structured `A2AMessage` envelopes on the
A2A bus (task, priority, reason, evidence, dependencies, result, confidence).

---

## 3. Permanent development rules

These rules are **non-negotiable** unless the human maintainer explicitly changes
them here.

1. **Inspect before acting.** At session start, read this file, then
   `PROJECT_STATUS.md` and `ROADMAP.md`, then survey the existing code. Build a
   mental model of what already exists.
2. **Preserve the architecture.** Do not flatten layers, bypass the DI
   container, or make `domain/` depend on infrastructure. New infrastructure
   implements a Protocol and is wired in `bootstrap.py`.
3. **Never regenerate completed code.** Do not rewrite, recreate, or "redo"
   modules that already exist and work. Extend them or add alongside. If a change
   to existing code is required, make the **smallest** correct edit.
4. **Continue from the next unfinished phase.** Check `PROJECT_STATUS.md` for the
   current milestone and `ROADMAP.md` for the sequence. Work the next incomplete
   item; do not jump ahead or restart earlier phases.
5. **Every component is replaceable and testable.** Inject Protocols, never
   concrete classes. New capabilities ship with tests.
6. **Async by default.** All I/O uses `asyncio`; never block the event loop
   (offload sync calls with `anyio.to_thread`).
7. **Passive by default; authorized only.** Active/intrusive capabilities must
   declare the right `ToolPermission` and require explicit opt-in. Respect
   `RECON_AUTHORIZED_ONLY` / `RECON_AUTHORIZED_TARGETS`.
8. **Graceful degradation.** Recon modules capture I/O errors into
   `ReconResult.errors` and never raise. The platform must run offline (LLM
   absent ⇒ deterministic fallback).
9. **No secrets in the repo.** Configuration comes from environment / a
   git-ignored `.env`. Never commit keys, tokens, cookies, or recon output.
10. **Keep it green.** `ruff check` and `pytest` must pass before you consider a
    change done. Update `CHANGELOG.md` and `PROJECT_STATUS.md` as work lands.

---

## 4. Coding standards

- **Language/runtime:** Python **3.11+** (developed on 3.12). Full type hints.
- **Models:** Pydantic v2 for all data contracts (`domain/schemas.py`).
- **Style:** `ruff` for lint + format (`line-length = 100`). Conventional
  Commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`).
- **LLM usage:** Anthropic Claude via `langchain-anthropic`. Use **adaptive
  thinking** + `output_config.effort`; never `budget_tokens` (removed on current
  models). Default model id is configurable (`RECON_LLM__MODEL`).
- **Errors:** raise from the `ReconPlatformError` hierarchy (`core/exceptions.py`).
- **Logging:** structured via `structlog` (`core.logging.get_logger`).
- **Docstrings:** module + public-class/function docstrings explaining intent and
  extension points, matching the surrounding density.
- **Tests:** `pytest` (+ `pytest-asyncio`, auto mode). Mock the network; keep
  tests hermetic and fast.

---

## 5. How to extend (cheat sheet)

| To add… | Do this |
|---|---|
| A recon module | Subclass `recon.base.ReconModule`; add to `build_passive_modules()`; test with mocked I/O. |
| A tool / plugin | Subclass `plugins.base.BaseTool` / `BasePlugin`; it surfaces via the MCP registry automatically. |
| A new agent | Subclass `agents.base.BaseAgent`; wire it in `orchestration/graph.py` and `bootstrap.py`. |
| A report format | Implement the `ReportRenderer` Protocol; register in `reporting/renderers.py`. |
| A different bus/memory/LLM | Implement the Protocol; rebind it in `bootstrap.py` only. |

---

## 6. Session start checklist

1. Read `CLAUDE.md` (this file), `PROJECT_STATUS.md`, `ROADMAP.md`.
2. Survey the repo; confirm what is already implemented.
3. Identify the **next unfinished phase/milestone**.
4. Plan the smallest correct change set; preserve existing code.
5. Implement with tests; run `ruff` + `pytest`.
6. Update `CHANGELOG.md` and `PROJECT_STATUS.md`.
