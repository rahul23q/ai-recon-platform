"""Desktop-agent infrastructure (Phase 4).

An OS-automation layer that mirrors the ``recon/``, ``browser/`` and ``vision/``
packages: ``DesktopModule``s observe and interact with the local desktop (window
discovery, screen capture, clipboard, and — gated — synthetic mouse/keyboard
input), driven by :class:`~recon_platform.agents.desktop.DesktopAgent`.

Everything here is **opt-in and off by default** (``settings.desktop.enabled``)
and behind a *two-key* safety posture: enabling the agent permits only read-only
observation; synthetic input additionally requires ``settings.desktop.allow_input``.
It degrades gracefully when no desktop backend is installed — the input backend,
window/clipboard/capture libraries are all imported lazily inside their providers,
so importing this package never requires the optional ``desktop`` extra.

Design seams (provider-independent, swappable — Dependency Inversion):

* :mod:`recon_platform.desktop.models` — pure value objects + the
  ``DesktopBackend`` interface for raw mouse/keyboard/screen primitives.
* :mod:`recon_platform.desktop.backends` — the ``null`` (no-op, always available)
  and ``pyautogui`` (real input) backends + a name-based factory.
* :mod:`recon_platform.desktop.manager` — :class:`DesktopManager`, the
  higher-level coordinator over a backend for windows / clipboard / capture.
* :mod:`recon_platform.desktop.session` — :class:`DesktopSession`, the action
  lifecycle wrapper (with the input safety gate) handed to the modules.

The Desktop agent reuses the Vision agent's detected on-screen elements
(``VISUAL_ELEMENT`` assets with bounding boxes), so it can plan clicks "by sight"
rather than at hard-coded coordinates — the perception → action chain the
roadmap's self-healing work builds on.
"""
