"""API-discovery infrastructure (Phase 7).

A characterization layer that mirrors the ``network/`` package: instead of
gathering new data it **correlates the endpoints, headers, JS files, and
classified API traffic already in the knowledge graph** (from passive recon, the
Browser agent, active recon, and the Network agent) to discover and describe the
APIs behind them. ``APIModule``s perform:

* **REST inference** — group endpoint URLs into REST APIs, inferring base path,
  version, resources, and request parameters.
* **GraphQL discovery** — surface GraphQL services (and likely introspection
  exposure) from classified traffic and endpoint paths.
* **SOAP / gRPC discovery** — detect ``?wsdl`` / ``.asmx`` / ``.svc`` (SOAP) and
  gRPC-web endpoints.
* **Auth-scheme detection** — infer authentication schemes (Bearer, Basic,
  Digest, API-key, cookie, OAuth) from request/response headers.

Everything here is **opt-in and off by default** (``settings.api_discovery.enabled``)
and dependency-free — it reads the graph and issues no new requests, so it always
degrades to a clean no-op when disabled.

Design seams:

* :mod:`recon_platform.api_discovery.detectors` — pure, dependency-free detection
  helpers (API-style classification, REST resource parsing, parameter extraction,
  auth-scheme detection, OpenAPI parsing) — the unit the hermetic tests exercise.
* :mod:`recon_platform.api_discovery.base` — the ``APIModule`` base + the
  ``APIDiscoveryContext`` snapshot handed to every module.
* :mod:`recon_platform.api_discovery.modules` — the concrete modules + the
  ``build_api_modules`` factory.
"""
