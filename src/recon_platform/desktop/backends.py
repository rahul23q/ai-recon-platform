"""Input-backend implementations + a name-based factory.

Two backends ship in Phase 4:

* :class:`NullDesktopBackend` — always available; records intended actions but
  performs nothing. The default used in tests and whenever the real input
  library is absent, so the platform never depends on a GUI being present.
* :class:`PyAutoGUIDesktopBackend` — drives real mouse/keyboard input and screen
  capture via the optional ``pyautogui`` library (imported lazily). ``available``
  is False until the library imports successfully.

:func:`build_desktop_backend` selects by name and falls back to the null backend
for unknown or uninstalled engines — mirroring ``build_ocr_provider`` in the
Vision package, so a run never crashes on a missing dependency.
"""

from __future__ import annotations

from recon_platform.core.logging import get_logger
from recon_platform.desktop.models import BaseDesktopBackend, ScreenRegion

log = get_logger(__name__)


class NullDesktopBackend(BaseDesktopBackend):
    """A no-op backend: records that an action was requested, performs nothing.

    Reports ``performed=False`` for every input call (the action history still
    captures intent), so the Desktop agent produces meaningful, hermetic output
    with no GUI, no display server, and no optional dependencies installed.
    """

    name = "null"

    @property
    def available(self) -> bool:
        # The null backend is always "available" as a recorder, but it never
        # performs real input — callers treat a null backend as no real desktop.
        return False

    def move(self, x: int, y: int, duration: float = 0.0) -> bool:
        return False

    def click(self, x: int, y: int, button: str = "left") -> bool:
        return False

    def type_text(self, text: str) -> bool:
        return False

    def press(self, *keys: str) -> bool:
        return False

    def screenshot(self, path: str) -> str | None:
        return None

    def screen_size(self) -> ScreenRegion | None:
        return None


class PyAutoGUIDesktopBackend(BaseDesktopBackend):
    """Real input + capture via ``pyautogui`` (lazy import).

    Every method swallows backend errors into a ``False`` / ``None`` return and a
    log line, so transient GUI failures never abort a run.
    """

    name = "pyautogui"

    def __init__(self) -> None:
        self._gui = None  # lazily resolved pyautogui module

    def _backend(self):  # noqa: ANN202 - returns the pyautogui module or None
        if self._gui is None:
            try:
                import pyautogui

                # Disable the library's own fail-safe-by-exception so a stray
                # corner move can't raise mid-run; we gate input ourselves.
                pyautogui.FAILSAFE = False
                self._gui = pyautogui
            except Exception as exc:  # noqa: BLE001
                log.warning("desktop.backend.import_failed", error=str(exc))
                self._gui = None
        return self._gui

    @property
    def available(self) -> bool:
        return self._backend() is not None

    def move(self, x: int, y: int, duration: float = 0.0) -> bool:
        gui = self._backend()
        if gui is None:
            return False
        try:
            gui.moveTo(x, y, duration=duration)
            return True
        except Exception as exc:  # noqa: BLE001
            log.warning("desktop.move.failed", error=str(exc))
            return False

    def click(self, x: int, y: int, button: str = "left") -> bool:
        gui = self._backend()
        if gui is None:
            return False
        try:
            gui.click(x=x, y=y, button=button)
            return True
        except Exception as exc:  # noqa: BLE001
            log.warning("desktop.click.failed", error=str(exc))
            return False

    def type_text(self, text: str) -> bool:
        gui = self._backend()
        if gui is None:
            return False
        try:
            gui.typewrite(text)
            return True
        except Exception as exc:  # noqa: BLE001
            log.warning("desktop.type.failed", error=str(exc))
            return False

    def press(self, *keys: str) -> bool:
        gui = self._backend()
        if gui is None:
            return False
        try:
            if len(keys) > 1:
                gui.hotkey(*keys)
            elif keys:
                gui.press(keys[0])
            return True
        except Exception as exc:  # noqa: BLE001
            log.warning("desktop.press.failed", error=str(exc))
            return False

    def screenshot(self, path: str) -> str | None:
        gui = self._backend()
        if gui is None:
            return None
        try:
            image = gui.screenshot()
            image.save(path)
            return path
        except Exception as exc:  # noqa: BLE001
            log.warning("desktop.screenshot.failed", error=str(exc))
            return None

    def screen_size(self) -> ScreenRegion | None:
        gui = self._backend()
        if gui is None:
            return None
        try:
            size = gui.size()
            return ScreenRegion(0, 0, int(size[0]), int(size[1]))
        except Exception as exc:  # noqa: BLE001
            log.warning("desktop.size.failed", error=str(exc))
            return None


#: Registry of known backends by name.
_BACKENDS = {
    "null": NullDesktopBackend,
    "pyautogui": PyAutoGUIDesktopBackend,
}


def build_desktop_backend(name: str) -> BaseDesktopBackend:
    """Return a backend by name, falling back to the null backend.

    A requested-but-unavailable real backend (e.g. ``pyautogui`` without the
    ``desktop`` extra, or no display server) also degrades to ``null`` so input
    is recorded as planned rather than crashing.
    """
    cls = _BACKENDS.get(name.lower(), NullDesktopBackend)
    backend = cls()
    if backend.name != "null" and not backend.available:
        log.info("desktop.backend.unavailable", requested=name, fallback="null")
        return NullDesktopBackend()
    return backend
