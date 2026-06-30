"""Desktop-agent tests — hermetic (no real mouse / keyboard / screen, no GUI libs).

Two layers, mirroring ``tests/test_vision.py``:

* **Unit** — the backend factory, the input safety gate (no synthetic input when
  ``allow_input`` is false), the clipboard fallback buffer, and the Vision
  element-centre helper are deterministic and dependency-free, so we test them
  directly with the always-available null backend / fakes.
* **Pipeline** — the desktop session + modules are stubbed via monkeypatch (no
  backend loads, ``desktop_available`` patched): disabled-by-default no-op,
  enabled-stubbed asset/finding flow, and graceful degradation when no desktop
  backend is installed.
"""

from __future__ import annotations

import pytest

from recon_platform.bootstrap import build_container
from recon_platform.core.config import Settings
from recon_platform.desktop.backends import (
    NullDesktopBackend,
    PyAutoGUIDesktopBackend,
    build_desktop_backend,
)
from recon_platform.desktop.manager import DesktopManager
from recon_platform.desktop.models import DesktopAction
from recon_platform.desktop.session import DesktopSession, element_center
from recon_platform.domain.enums import AgentRole, AssetType
from recon_platform.domain.schemas import Asset, EngagementContext, ReconResult
from recon_platform.orchestration.graph import ReconOrchestrator
from recon_platform.recon.base import ReconModule


# ---------------------------------------------------------------------------
# Unit tests (no models, no GUI)
# ---------------------------------------------------------------------------
def test_build_backend_falls_back_to_null_for_unknown():
    backend = build_desktop_backend("does-not-exist")
    assert backend.name == "null"


def test_build_backend_pyautogui_falls_back_when_unavailable():
    # In the hermetic test env pyautogui is not installed, so a requested real
    # backend degrades to the null recorder rather than crashing.
    backend = build_desktop_backend("pyautogui")
    assert backend.name == "null"


def test_null_backend_performs_nothing():
    backend = NullDesktopBackend()
    assert backend.available is False
    assert backend.move(1, 2) is False
    assert backend.click(1, 2) is False
    assert backend.type_text("x") is False
    assert backend.screenshot("x.png") is None


def test_pyautogui_backend_unavailable_without_lib():
    # The class imports its dependency lazily; absent the lib it reports
    # unavailable and never raises on construction.
    assert PyAutoGUIDesktopBackend().available is False


def test_element_center_computes_box_midpoint():
    assert element_center({"x": 10, "y": 20, "width": 100, "height": 40}) == (60, 40)


def test_clipboard_roundtrips_via_buffer_fallback():
    # Without pyperclip, set/get round-trips through the in-process buffer.
    mgr = DesktopManager(_desktop_settings())
    mgr.set_clipboard("hello")
    assert mgr.get_clipboard() == "hello"


async def test_safety_gate_blocks_input_when_disabled():
    """allow_input=False ⇒ clicks are recorded as planned (dry-run), not sent."""
    settings = _desktop_settings(allow_input=False)
    sent: list[str] = []

    async with DesktopSession(settings) as session:
        # Replace the manager's click with a spy so we can assert it is NOT called.
        session.manager.click = lambda *a, **k: sent.append("click") or True  # type: ignore[assignment]
        action = session.click_at(5, 5)

    assert isinstance(action, DesktopAction)
    assert action.performed is False
    assert action.attributes.get("dry_run") == "true"
    assert sent == []  # backend never invoked in safe mode


async def test_safety_gate_allows_input_when_enabled():
    """allow_input=True ⇒ the backend is actually invoked."""
    settings = _desktop_settings(allow_input=True)
    sent: list[str] = []

    async with DesktopSession(settings) as session:
        session.manager.click = lambda *a, **k: sent.append("click") or True  # type: ignore[assignment]
        action = session.click_at(5, 5)

    assert action.performed is True
    assert sent == ["click"]


# ---------------------------------------------------------------------------
# Pipeline stubs
# ---------------------------------------------------------------------------
class _StubReconModule(ReconModule):
    name = "stub"
    description = "offline stub"

    async def run(self, ctx) -> ReconResult:  # noqa: ANN001
        return ReconResult(
            task_id="",
            module=self.name,
            assets=[Asset(type=AssetType.DOMAIN, value=ctx.target, source="stub")],
            notes=["stub ran"],
        )


class _StubDesktopModule:
    """Stand-in desktop module returning window + action + screenshot assets."""

    name = "stub_desktop"
    description = "offline desktop stub"
    permissions = ()

    async def run(self, ctx) -> ReconResult:  # noqa: ANN001
        return ReconResult(
            task_id="",
            module=self.name,
            assets=[
                Asset(
                    type=AssetType.WINDOW,
                    value="Login - Example",
                    source="stub_desktop",
                    attributes={"active": True, "via": "desktop"},
                ),
                Asset(
                    type=AssetType.DESKTOP_ACTION,
                    value="click:click login button",
                    source="stub_desktop",
                    attributes={
                        "action_type": "click",
                        "performed": "False",
                        "via": "desktop",
                        "dry_run": "true",
                    },
                ),
                Asset(
                    type=AssetType.SCREENSHOT,
                    value="reports/desktop/example.com.desktop.png",
                    source="stub_desktop",
                    attributes={"via": "desktop"},
                ),
            ],
            notes=["stub desktop ran"],
        )


class _FakeDesktopSession:
    """Async-context-manager stand-in for DesktopSession (no backend loads)."""

    def __init__(self, settings) -> None:  # noqa: ANN001
        self._settings = settings

    async def __aenter__(self) -> _FakeDesktopSession:
        return self

    async def __aexit__(self, *exc) -> None:  # noqa: ANN002
        return None


@pytest.fixture(autouse=True)
def _patch_recon_modules(monkeypatch):
    factory = lambda: [_StubReconModule()]  # noqa: E731
    monkeypatch.setattr("recon_platform.agents.recon.build_passive_modules", factory)
    monkeypatch.setattr("recon_platform.agents.planner.build_passive_modules", factory)


def _disabled_settings() -> Settings:
    settings = Settings(authorized_only=False)
    settings.llm.enabled = False
    return settings


def _desktop_settings(allow_input: bool = False) -> Settings:
    settings = _disabled_settings()
    settings.desktop.enabled = True
    settings.desktop.allow_input = allow_input
    return settings


async def test_desktop_disabled_by_default_is_noop():
    settings = _disabled_settings()
    assert settings.desktop.enabled is False
    container = build_container(settings)
    orch = ReconOrchestrator(container)

    bundle = await orch.run(EngagementContext(target="example.com"))

    assert bundle.plan is not None and len(bundle.plan.tasks) == 3
    assert not any(a.type == AssetType.WINDOW for a in bundle.assets)
    assert not any(a.type == AssetType.DESKTOP_ACTION for a in bundle.assets)


async def test_desktop_enabled_stubbed_produces_assets_and_findings(monkeypatch):
    monkeypatch.setattr("recon_platform.agents.desktop.desktop_available", lambda: True)
    monkeypatch.setattr("recon_platform.agents.desktop.DesktopSession", _FakeDesktopSession)
    monkeypatch.setattr(
        "recon_platform.agents.desktop.build_desktop_modules",
        lambda: [_StubDesktopModule()],
    )

    container = build_container(_desktop_settings())
    orch = ReconOrchestrator(container)

    bundle = await orch.run(EngagementContext(target="example.com"))

    # Desktop assets reached the knowledge graph.
    assert any(a.type == AssetType.WINDOW for a in bundle.assets)
    assert any(a.type == AssetType.DESKTOP_ACTION for a in bundle.assets)

    titles = [f.title.lower() for f in bundle.findings]
    assert any("desktop automation" in t for t in titles)

    # The report renders a Desktop Automation section.
    from recon_platform.reporting.renderers import get_renderer

    md = get_renderer("markdown").render(bundle)
    assert "Desktop Automation" in md
    assert "planned (dry-run)" in md  # the stub action was not performed

    assert bundle.plan is not None and len(bundle.plan.tasks) == 3


async def test_desktop_graceful_degradation_when_backend_missing(monkeypatch):
    monkeypatch.setattr("recon_platform.agents.desktop.desktop_available", lambda: False)

    container = build_container(_desktop_settings())
    orch = ReconOrchestrator(container)

    bundle = await orch.run(EngagementContext(target="example.com"))

    skips = [
        t for t in bundle.traces if t.agent == AgentRole.DESKTOP and t.action == "skip"
    ]
    assert skips, "expected a desktop skip trace"
    assert not any(a.type == AssetType.WINDOW for a in bundle.assets)
