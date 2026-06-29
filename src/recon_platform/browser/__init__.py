"""Browser-agent infrastructure (Phase 2).

A Playwright + Chrome DevTools layer that mirrors the passive ``recon/`` package:
``BrowserModule``s run against a live, navigated page and return ``ReconResult``s,
driven by the :class:`~recon_platform.agents.browser.BrowserAgent`.

Everything here is **opt-in and off by default** (``settings.browser.enabled``)
and degrades gracefully when Playwright is absent — Playwright is imported lazily
inside :mod:`recon_platform.browser.session` only, so importing this package never
requires the optional ``browser`` extra.
"""
