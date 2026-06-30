"""Desktop value objects + the input-backend interface.

Framework-agnostic dataclasses exchanged between the input backends, the
:class:`~recon_platform.desktop.manager.DesktopManager`, the session, and the
modules. They deliberately avoid any heavy dependency (no pyautogui / pygetwindow
here) so the contracts are importable anywhere — the concrete backends import
their libraries lazily.

``DesktopBackend`` is the seam that keeps the Desktop agent provider-independent:
the ``null`` backend records intended actions without performing them (used by
default and in tests), while a ``pyautogui`` backend performs real input. New
backends (e.g. an X11 / Wayland / remote-VNC driver) implement this interface and
are wired by name in :mod:`recon_platform.desktop.backends`.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class ScreenRegion:
    """An axis-aligned screen region in pixel coordinates (origin top-left)."""

    x: int
    y: int
    width: int
    height: int

    def as_dict(self) -> dict[str, int]:
        return {"x": self.x, "y": self.y, "width": self.width, "height": self.height}

    @property
    def center(self) -> tuple[int, int]:
        return (self.x + self.width // 2, self.y + self.height // 2)


@dataclass(frozen=True)
class WindowInfo:
    """A discovered OS window."""

    title: str
    handle: str = ""
    region: ScreenRegion | None = None
    is_active: bool = False

    def as_dict(self) -> dict[str, object]:
        d: dict[str, object] = {
            "title": self.title,
            "handle": self.handle,
            "is_active": self.is_active,
        }
        if self.region is not None:
            d["region"] = self.region.as_dict()
        return d


@dataclass
class DesktopAction:
    """A record of one desktop interaction (performed or, in safe mode, planned).

    ``performed`` is False when the action was recorded but not actually executed
    — either because the ``null`` backend is in use or because synthetic input is
    disabled (``allow_input=False``). ``error`` captures any failure so the action
    history is always complete and the modules never raise.
    """

    kind: str  # mouse_move | click | type | hotkey | clipboard | screen_capture | file_dialog
    detail: str = ""
    x: int | None = None
    y: int | None = None
    performed: bool = False
    error: str | None = None
    attributes: dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "detail": self.detail,
            "x": self.x,
            "y": self.y,
            "performed": self.performed,
            "error": self.error,
            **self.attributes,
        }


@runtime_checkable
class DesktopBackend(Protocol):
    """Interface for the raw input + capture primitives.

    Concrete backends (``null``, ``pyautogui``, future remote drivers) implement
    this without changing any agent or module code. Every method must be
    resilient — return ``False`` / ``None`` on failure rather than raising — so a
    flaky backend never aborts a run.
    """

    name: str

    @property
    def available(self) -> bool:
        """True when this backend can actually drive the desktop."""
        ...

    def move(self, x: int, y: int, duration: float = 0.0) -> bool: ...

    def click(self, x: int, y: int, button: str = "left") -> bool: ...

    def type_text(self, text: str) -> bool: ...

    def press(self, *keys: str) -> bool: ...

    def screenshot(self, path: str) -> str | None: ...

    def screen_size(self) -> ScreenRegion | None: ...


class BaseDesktopBackend(abc.ABC):
    """Convenience ABC for concrete backends with a shared resilient contract."""

    name: str = "base"

    @property
    @abc.abstractmethod
    def available(self) -> bool:
        raise NotImplementedError

    @abc.abstractmethod
    def move(self, x: int, y: int, duration: float = 0.0) -> bool:
        raise NotImplementedError

    @abc.abstractmethod
    def click(self, x: int, y: int, button: str = "left") -> bool:
        raise NotImplementedError

    @abc.abstractmethod
    def type_text(self, text: str) -> bool:
        raise NotImplementedError

    @abc.abstractmethod
    def press(self, *keys: str) -> bool:
        raise NotImplementedError

    @abc.abstractmethod
    def screenshot(self, path: str) -> str | None:
        raise NotImplementedError

    def screen_size(self) -> ScreenRegion | None:  # pragma: no cover - optional
        return None
