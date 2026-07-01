"""Network-agent infrastructure (Phase 6).

A request/response analysis layer that mirrors the ``recon/`` / ``vision/`` /
``desktop/`` packages, but instead of gathering new data it **correlates network
observations already in the knowledge graph** — the HTTP headers, cookies,
tokens, endpoints, and captured traffic produced by passive recon, the Browser
agent, and active recon. ``NetworkModule``s perform:

* **JWT inspection** — decode JSON Web Tokens found in headers / tokens / URLs
  (header + payload only; signatures are never verified) and flag weaknesses.
* **Header / CORS hygiene** — spot dangerous cross-origin configurations.
* **API traffic classification** — mark endpoints as GraphQL or REST traffic and
  flag likely GraphQL introspection exposure.
* **WebSocket review** — surface ``ws://`` / ``wss://`` endpoints and flag
  unencrypted ones.

Everything here is **opt-in and off by default** (``settings.network.enabled``)
and dependency-free — it reads the graph and issues no new requests, so it always
degrades to a clean no-op when disabled.

Design seams:

* :mod:`recon_platform.network.detectors` — pure, dependency-free detection
  helpers (JWT decode, endpoint classification, CORS checks) — the unit the
  hermetic tests exercise directly.
* :mod:`recon_platform.network.base` — the ``NetworkModule`` base + the
  ``NetworkContext`` snapshot handed to every module.
* :mod:`recon_platform.network.modules` — the concrete modules + the
  ``build_network_modules`` factory.
"""
