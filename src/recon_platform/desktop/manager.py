"""DesktopManager — higher-level coordinator over a desktop input backend.

Owns the configured :class:`~recon_platform.desktop.models.DesktopBackend` and
adds the "environment" capabilities that sit above raw input: window discovery
and management, clipboard read/write, and screen capture. The heavy libraries
(``pygetwindow``, ``pyperclip``, ``mss`` / ``Pillow``) are imported **lazily** and
only when present; every method is resilient and returns empty / ``None`` on
failure rather than raising, so the manager works headless and dependency-free.

Clipboard operations fall back to an in-process buffer when ``pyperclip`` is
absent, so set/get round-trips remain testable offline.
"""

from __future__ import annotations

from recon_platform.core.config import Settings
from recon_platform.core.logging import get_logger
from recon_platform.desktop.backends import build_desktop_backend
from recon_platform.desktop.models import BaseDesktopBackend, ScreenRegion, WindowInfo

log = get_logger(__name__)


class DesktopManager:
    """Coordinates window / clipboard / capture operations over an input backend.

    The backend (raw mouse/keyboard/screenshot primitives) is resolved by name
    from settings; the manager layers the higher-level desktop operations on top.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self.backend: BaseDesktopBackend = build_desktop_backend(settings.desktop.backend)
        # In-process clipboard fallback when pyperclip is unavailable.
        self._clipboard_buffer: str = ""

    # -- input passthroughs (raw primitives) --------------------------------
    def move(self, x: int, y: int) -> bool:
        return self.backend.move(x, y, duration=self._settings.desktop.move_duration)

    def click(self, x: int, y: int, button: str = "left") -> bool:
        return self.backend.click(x, y, button=button)

    def type_text(self, text: str) -> bool:
        return self.backend.type_text(text)

    def press(self, *keys: str) -> bool:
        return self.backend.press(*keys)

    def screen_size(self) -> ScreenRegion | None:
        return self.backend.screen_size()

    # -- window discovery / management --------------------------------------
    def discover_windows(self) -> list[WindowInfo]:
        """Enumerate open OS windows (best-effort via ``pygetwindow``)."""
        try:
            import pygetwindow as gw
        except Exception:  # noqa: BLE001 - library absent / headless
            return []
        windows: list[WindowInfo] = []
        try:
            active = gw.getActiveWindow()
            active_title = getattr(active, "title", None)
            for w in gw.getAllWindows():
                title = (getattr(w, "title", "") or "").strip()
                if not title:
                    continue
                region: ScreenRegion | None = None
                try:
                    region = ScreenRegion(int(w.left), int(w.top), int(w.width), int(w.height))
                except Exception:  # noqa: BLE001
                    region = None
                windows.append(
                    WindowInfo(
                        title=title,
                        handle=str(getattr(w, "_hWnd", "") or getattr(w, "_handle", "")),
                        region=region,
                        is_active=(title == active_title),
                    )
                )
        except Exception as exc:  # noqa: BLE001
            log.warning("desktop.windows.failed", error=str(exc))
            return []
        return windows[: self._settings.desktop.max_windows]

    def activate_window(self, title: str) -> bool:
        """Bring the first window whose title contains ``title`` to the front."""
        try:
            import pygetwindow as gw

            matches = gw.getWindowsWithTitle(title)
            if not matches:
                return False
            matches[0].activate()
            return True
        except Exception as exc:  # noqa: BLE001
            log.warning("desktop.activate.failed", title=title, error=str(exc))
            return False

    # -- clipboard ----------------------------------------------------------
    def get_clipboard(self) -> str:
        try:
            import pyperclip

            return pyperclip.paste() or ""
        except Exception:  # noqa: BLE001
            return self._clipboard_buffer

    def set_clipboard(self, text: str) -> bool:
        self._clipboard_buffer = text
        try:
            import pyperclip

            pyperclip.copy(text)
            return True
        except Exception:  # noqa: BLE001 - keep the buffer fallback only
            return False

    # -- screen capture -----------------------------------------------------
    def capture_screen(self, path: str) -> str | None:
        """Capture the full screen to ``path`` (best-effort).

        Tries the backend's native screenshot first (pyautogui), then ``mss``,
        then ``PIL.ImageGrab`` — returning the first that succeeds, or ``None``.
        """
        native = self.backend.screenshot(path)
        if native:
            return native
        try:
            import mss
            import mss.tools

            with mss.mss() as sct:
                shot = sct.grab(sct.monitors[0])
                mss.tools.to_png(shot.rgb, shot.size, output=path)
            return path
        except Exception:  # noqa: BLE001
            pass
        try:
            from PIL import ImageGrab

            ImageGrab.grab().save(path)
            return path
        except Exception:  # noqa: BLE001
            return None
