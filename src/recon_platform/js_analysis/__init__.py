"""JavaScript-analysis infrastructure (Phase 8).

Maps the **client-side attack surface** by analyzing the JavaScript the target
serves. Unlike the Network / API-discovery agents (pure graph correlators), this
family performs *passive* outbound fetches — GET-only retrieval of the ``.js``
files the app already references (the ``JS_FILE`` assets the Browser agent
inventoried, plus passive recon) — and then reasons over the text purely:

* **Endpoint extraction** — pull URLs / API paths / ``fetch``/``axios``/XHR
  targets out of bundles → ``ENDPOINT`` assets (tagged ``via=js``) that feed the
  Network and API-discovery agents.
* **Secret detection** — high-signal keys/tokens embedded in scripts →
  ``SECRET`` assets (tagged ``via=js``), reusing the shared secret patterns.
* **Source-map discovery** — ``//# sourceMappingURL=`` references and ``.map``
  files that can reconstruct original source → ``SOURCE_MAP`` assets.

Everything here is **opt-in and off by default** (``settings.js_analysis.enabled``)
and self-degrading: with fetching disabled or offline it produces no results and
never raises. The fetch step is GET-only and declares ``NETWORK_PASSIVE`` — the
same posture as the passive-recon modules.

Design seams:

* :mod:`recon_platform.js_analysis.analyzers` — pure, dependency-free extraction
  helpers (endpoints, parameters, source maps) — the unit the hermetic tests
  exercise directly.
* :mod:`recon_platform.js_analysis.fetcher` — the GET-only ``fetch_js`` helper.
* :mod:`recon_platform.js_analysis.base` — the ``JSModule`` base + the ``JSContext``
  snapshot handed to every module.
* :mod:`recon_platform.js_analysis.modules` — the concrete modules + the
  ``build_js_modules`` factory.
"""
