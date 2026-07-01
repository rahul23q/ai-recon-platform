"""Authentication-workflow infrastructure (Phase 9).

Drives authentication flows against the target — **login**, **registration**,
**forgot-password**, and **admin-panel** probes — and captures the resulting
authenticated session (cookies) for downstream agents to reuse.

Unlike the passive analysis agents, authenticating is **active/intrusive**
(it submits credentials), so the :class:`~recon_platform.agents.auth.AuthenticationAgent`
sits behind a *two-key* posture (``enabled`` + ``authorized``) plus the engagement
authorization gate, exactly like active recon. Credentials are supplied via the
environment as ``SecretStr`` and masked everywhere they surface.

The design keeps the reasoning **pure and Playwright-free** so it is hermetically
testable:

* :mod:`recon_platform.auth.forms` — pure form/field heuristics (classify inputs,
  locate username/email/password/submit, decide login success). Directly unit-tested.
* :mod:`recon_platform.auth.discovery` — pure candidate-URL selection from the
  knowledge graph (login / register / forgot / admin paths).
* :mod:`recon_platform.auth.credentials` — a ``SecretStr``-backed credential holder
  with masking.
* :mod:`recon_platform.auth.models` — the ``AuthResult`` / ``CapturedSession``
  value objects.
* :mod:`recon_platform.auth.page` — the ``AuthPage`` protocol (the minimal page
  operations the workflows need), the Playwright-backed implementation, and the
  ``open_auth_page`` factory seam the agent (and tests) drive.
* :mod:`recon_platform.auth.workflows` — the concrete workflows + ``build_workflows``.
"""
