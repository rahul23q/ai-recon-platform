"""DesktopSession — the desktop action lifecycle wrapper.

The Phase-4 counterpart to :class:`~recon_platform.vision.session.VisionSession`
and :class:`~recon_platform.browser.session.BrowserSession`. It owns a
:class:`~recon_platform.desktop.manager.DesktopManager`, exposes a unified action
API to the modules, records every interaction in :attr:`actions`, and enforces
the **input safety gate**: synthetic mouse/keyboard input fires only when
``settings.desktop.allow_input`` is true; otherwise the action is recorded as a
*planned* (dry-run) :class:`~recon_platform.desktop.models.DesktopAction` and no
real input is sent. Read-only operations (window discovery, screen capture,
clipboard read) are always allowed when the agent is enabled.

The heavy stack is imported lazily by the manager / backends, so callers gate on
:func:`desktop_available` and skip cleanly otherwise — the same degradation
pattern the Browser / Vision layers use.
"""

from __future__ import annotations

from types import TracebackType

from recon_platform.core.config import Settings
from recon_platform.core.logging import get_logger
from recon_platform.desktop.manager import DesktopManager
from recon_platform.desktop.models import DesktopAction, ScreenRegion, WindowInfo

log = get_logger(__name__)

# Modules that, if any is importable, make real desktop automation possible.
_DESKTOP_BACKENDS = ("pyautogui", "pygetwindow", "pyperclip", "mss", "PIL")


def desktop_available() -> bool:
    """True when at least one desktop backend can be imported.

    Mirrors ``vision_available`` / ``playwright_available`` — a cheap lazy probe
    so the desktop step degrades to a no-op when the optional ``desktop`` extra is
    not installed (or no display server is present).
    """
    for mod in _DESKTOP_BACKENDS:
        try:
            __import__(mod)
            return True
        except Exception:  # noqa: BLE001
            continue
    return False


class DesktopSession:
    """Owns the desktop manager and records every (planned or performed) action.

    Usage::

        async with DesktopSession(settings) as session:
            windows = session.discover_windows()
            session.click_at(100, 200)          # gated by allow_input

    Resilient throughout: a failed interaction is captured on the
    :class:`~recon_platform.desktop.models.DesktopAction` (``error``) rather than
    raised, so one bad action never aborts a run.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self.manager = DesktopManager(settings)
        #: Ordered history of every action attempted during the session.
        self.actions: list[DesktopAction] = []

    # -- lifecycle (symmetry with Browser / Vision sessions) ----------------
    async def __aenter__(self) -> DesktopSession:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        return None

    # -- safety -------------------------------------------------------------
    @property
    def input_allowed(self) -> bool:
        """True when synthetic input may actually be sent (the second key)."""
        return bool(self._settings.desktop.allow_input)

    def _record(self, action: DesktopAction) -> DesktopAction:
        self.actions.append(action)
        return action

    # -- read-only observation ---------------------------------------------
    def discover_windows(self) -> list[WindowInfo]:
        return self.manager.discover_windows()

    def screen_size(self) -> ScreenRegion | None:
        return self.manager.screen_size()

    def capture_screen(self, path: str) -> DesktopAction:
        result = self.manager.capture_screen(path)
        return self._record(
            DesktopAction(
                kind="screen_capture",
                detail=path if result else "capture unavailable",
                performed=bool(result),
                error=None if result else "no screen-capture backend",
                attributes={"path": result or ""},
            )
        )

    def read_clipboard(self) -> DesktopAction:
        text = self.manager.get_clipboard()
        return self._record(
            DesktopAction(
                kind="clipboard",
                detail="read clipboard",
                performed=True,
                attributes={"op": "read", "length": str(len(text)), "preview": text[:120]},
            )
        )

    # -- gated input --------------------------------------------------------
    def move_to(self, x: int, y: int, *, label: str = "") -> DesktopAction:
        return self._gated(
            kind="mouse_move",
            detail=label or f"move to ({x}, {y})",
            x=x,
            y=y,
            perform=lambda: self.manager.move(x, y),
        )

    def click_at(self, x: int, y: int, *, button: str = "left", label: str = "") -> DesktopAction:
        return self._gated(
            kind="click",
            detail=label or f"{button} click at ({x}, {y})",
            x=x,
            y=y,
            perform=lambda: self.manager.click(x, y, button=button),
            attributes={"button": button},
        )

    def type_text(self, text: str, *, label: str = "") -> DesktopAction:
        return self._gated(
            kind="type",
            detail=label or f"type {len(text)} char(s)",
            perform=lambda: self.manager.type_text(text),
            attributes={"length": str(len(text))},
        )

    def hotkey(self, *keys: str) -> DesktopAction:
        combo = "+".join(keys)
        return self._gated(
            kind="hotkey",
            detail=f"press {combo}",
            perform=lambda: self.manager.press(*keys),
            attributes={"keys": combo},
        )

    def set_clipboard(self, text: str) -> DesktopAction:
        return self._gated(
            kind="clipboard",
            detail=f"write {len(text)} char(s) to clipboard",
            perform=lambda: self.manager.set_clipboard(text),
            attributes={"op": "write", "length": str(len(text))},
        )

    def handle_file_dialog(self, path: str, *, confirm: bool = True) -> DesktopAction:
        """Drive a native file-upload/download dialog: type ``path`` then Enter.

        A common desktop-automation need the browser cannot satisfy (OS file
        choosers). Gated like any other input — in safe mode it is recorded as a
        planned action so the intended path is auditable without touching the UI.
        """
        def _perform() -> bool:
            ok = self.manager.type_text(path)
            if confirm:
                ok = self.manager.press("enter") and ok
            return ok

        return self._gated(
            kind="file_dialog",
            detail=f"enter path into file dialog: {path}",
            perform=_perform,
            attributes={"path": path, "confirm": str(confirm)},
        )

    def click_element(self, box: dict, *, label: str = "") -> DesktopAction:
        """Click the centre of a Vision-detected element's bounding box.

        ``box`` is the ``{x, y, width, height}`` dict that the Vision agent stores
        on ``VISUAL_ELEMENT`` assets — this is the perception → action bridge.
        """
        cx, cy = element_center(box)
        return self.click_at(cx, cy, label=label or "click detected element")

    # -- internal -----------------------------------------------------------
    def _gated(
        self,
        *,
        kind: str,
        detail: str,
        perform,  # noqa: ANN001 - callable[[], bool]
        x: int | None = None,
        y: int | None = None,
        attributes: dict[str, str] | None = None,
    ) -> DesktopAction:
        """Run ``perform`` only when input is allowed; always record the action."""
        attrs = dict(attributes or {})
        if not self.input_allowed:
            attrs["dry_run"] = "true"
            return self._record(
                DesktopAction(kind=kind, detail=detail, x=x, y=y, performed=False, attributes=attrs)
            )
        try:
            ok = bool(perform())
        except Exception as exc:  # noqa: BLE001
            return self._record(
                DesktopAction(
                    kind=kind, detail=detail, x=x, y=y, performed=False,
                    error=str(exc), attributes=attrs,
                )
            )
        return self._record(
            DesktopAction(
                kind=kind, detail=detail, x=x, y=y, performed=ok,
                error=None if ok else "backend reported no-op", attributes=attrs,
            )
        )


def element_center(box: dict) -> tuple[int, int]:
    """Return the centre point of a ``{x, y, width, height}`` bounding box."""
    x = int(box.get("x", 0))
    y = int(box.get("y", 0))
    w = int(box.get("width", 0))
    h = int(box.get("height", 0))
    return (x + w // 2, y + h // 2)
