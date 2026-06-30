"""Active-recon infrastructure (Phase 5).

A provider-independent **external-tool framework** that integrates best-of-breed
security binaries (httpx, subfinder, naabu, katana, gau, amass, dirsearch, ffuf,
nuclei, nmap) as first-class plugins, mirroring the ``recon/`` / ``desktop/``
packages. Each tool is wrapped behind a uniform :class:`ExternalTool` contract:
it builds a command line, runs it through the shared async
:class:`~recon_platform.active_recon.runner.ToolRunner` (timeout + retries +
cancellation), and normalizes the captured stdout into the platform's common
domain models (``Asset`` / ``Relation``) for the knowledge graph.

Everything here is **opt-in and off by default** (``settings.active_recon.enabled``)
behind a *two-key* authorization posture, and degrades gracefully — tools are
discovered on ``PATH`` and **never imported**, so a missing binary is skipped
cleanly and the platform installs and runs without any of them present.

Design seams (provider-independent, swappable — Dependency Inversion):

* :mod:`recon_platform.active_recon.models` — the ``ToolExecution`` record
  (command / stdout / stderr / exit code / duration / parsed result).
* :mod:`recon_platform.active_recon.runner` — the async subprocess runner with
  timeout, retries, and cancellation, plus a ``binary_available`` probe.
* :mod:`recon_platform.active_recon.base` — the ``ExternalTool`` framework + the
  ``ActiveToolContext`` handed to every tool.
* :mod:`recon_platform.active_recon.tools` — the ten concrete tool wrappers and
  the ``build_active_tools`` factory.
"""
