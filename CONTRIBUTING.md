# Contributing to recon-platform

Thanks for your interest! This project is built as a **Clean-Architecture,
SOLID, dependency-injected** platform that grows module-by-module. Contributions
that respect those seams are easy to review and integrate.

> ⚠️ **Authorized use only.** Do not contribute capabilities designed to evade
> detection or to enable unauthorized or mass-targeting activity. See
> [SECURITY.md](SECURITY.md).

## Getting started

```bash
git clone <your-fork-url> && cd recon-platform
py -3.12 -m venv .venv && .venv\Scripts\activate   # macOS/Linux: source .venv/bin/activate
pip install -e ".[dev]"        # add ".[llm,api]" to work on those areas
pytest                         # all tests should pass
```

Python **3.11+** is required (developed and verified on 3.12).

## Development workflow

1. Create a branch off `main`.
2. Make your change with tests.
3. Run the quality gates locally:
   ```bash
   ruff check src tests        # lint
   ruff format src tests       # format (optional but encouraged)
   pytest                      # tests
   ```
4. Open a pull request describing **what** and **why**.

## Architecture rules (please follow)

- **Depend inward.** `domain/` defines `Protocol` contracts; everything else
  depends on those, not on concretions. New infrastructure implements a
  Protocol and is wired in `bootstrap.py` — nowhere else.
- **Every component is replaceable and testable.** No agent should import a
  concrete bus/memory/LLM; inject the Protocol.
- **Async everywhere.** I/O is `asyncio`; never block the event loop (use
  `anyio.to_thread` for sync calls).
- **Recon modules must degrade gracefully.** Capture I/O failures into
  `ReconResult.errors`; never raise out of a module.
- **Passive by default.** Active/intrusive capabilities must declare the
  appropriate `ToolPermission` and require explicit opt-in.

## Adding things

- **A recon module:** subclass `recon.base.ReconModule`, add it to
  `build_passive_modules()`, and write a test (mock the network).
- **A tool/plugin:** subclass `plugins.base.BaseTool` / `BasePlugin`; it is
  surfaced automatically through the MCP registry.
- **A renderer:** implement the `ReportRenderer` Protocol and register it in
  `reporting/renderers.py`.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/) where
practical: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`.

## Code of conduct

Be respectful and constructive. Harassment or abuse is not tolerated.
