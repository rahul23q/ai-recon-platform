"""Vision-agent tests — hermetic (no OCR model downloads, no image libraries).

Two layers:

* **Pure functions** — the heuristic detector, page classifier, and text
  extractors are deterministic and dependency-free, so we test them directly.
* **Pipeline** — the vision session + modules are stubbed via monkeypatch (no
  model loads, ``vision_available`` patched), mirroring ``tests/test_browser.py``:
  disabled-by-default no-op, enabled-stubbed asset/finding flow, and graceful
  degradation when no vision backend is installed.
"""

from __future__ import annotations

import pytest

from recon_platform.bootstrap import build_container
from recon_platform.core.config import Settings
from recon_platform.domain.enums import AgentRole, AssetType
from recon_platform.domain.schemas import Asset, EngagementContext, ReconResult
from recon_platform.orchestration.graph import ReconOrchestrator
from recon_platform.recon.base import ReconModule
from recon_platform.vision.base import VisionModule
from recon_platform.vision.detector import (
    HeuristicDetector,
    classify_page,
    extract_emails,
    extract_phones,
    find_secrets,
)
from recon_platform.vision.models import BoundingBox, OCRResult, OCRToken


# ---------------------------------------------------------------------------
# Pure-function tests (no models, no images)
# ---------------------------------------------------------------------------
def test_classify_page_detects_login_portal():
    text = "Sign in\nUsername\nPassword\nForgot password?"
    result = classify_page(text)
    assert result.page_type == "login_portal"
    assert result.confidence > 0.0


def test_classify_page_detects_swagger():
    assert classify_page("Swagger UI\nTry it out\nOpenAPI").page_type == "swagger_ui"


def test_extract_emails_and_phones():
    text = "Contact us at admin@example.com or call +1 (415) 555-2671."
    assert "admin@example.com" in extract_emails(text)
    assert extract_phones(text)


def test_find_secrets_detects_jwt_and_aws_key():
    jwt = "eyJhbGciOiJIUzI1Niosffd.eyJzdWIiOiIxMjM0NTYiabcd.SflKxwRJSMeKKF2QT4fwpM"
    text = f"token={jwt} key=AKIAIOSFODNN7EXAMPLE"
    kinds = {k for k, _ in find_secrets(text)}
    assert "jwt" in kinds
    assert "aws_access_key" in kinds


async def test_heuristic_detector_finds_login_form():
    ocr = OCRResult(
        provider="stub",
        tokens=[
            OCRToken(text="Username", confidence=0.9, box=BoundingBox(0, 0, 80, 20)),
            OCRToken(text="Password", confidence=0.9, box=BoundingBox(0, 30, 80, 20)),
            OCRToken(text="Submit", confidence=0.8, box=BoundingBox(0, 60, 60, 24)),
        ],
    )
    objects = await HeuristicDetector().detect("img.png", ocr)
    labels = {o.label for o in objects}
    assert "login_form" in labels
    assert "button" in labels


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


class _StubVisionModule(VisionModule):
    name = "stub_vision"
    description = "offline vision stub"

    async def run(self, ctx) -> ReconResult:  # noqa: ANN001
        return ReconResult(
            task_id="",
            module=self.name,
            assets=[
                Asset(
                    type=AssetType.SCREENSHOT,
                    value="reports/screenshots/example.com.png",
                    source="stub_vision",
                    attributes={
                        "page_type": "login_portal",
                        "page_confidence": 0.8,
                        "elements": 2,
                        "ocr_provider": "stub",
                        "via": "vision",
                    },
                ),
                Asset(
                    type=AssetType.VISUAL_ELEMENT,
                    value="login_form@example.com.png#0",
                    source="stub_vision",
                    attributes={"element_type": "login_form", "confidence": 0.9},
                ),
                Asset(
                    type=AssetType.SECRET,
                    value="AKIAIOSFODNN7EXAMPLE",
                    source="stub_vision",
                    attributes={"kind": "aws_access_key", "from": "ocr"},
                ),
                Asset(
                    type=AssetType.EMAIL,
                    value="admin@example.com",
                    source="stub_vision",
                    attributes={"from": "ocr"},
                ),
            ],
            notes=["stub vision ran"],
        )


class _FakeVisionSession:
    """Async-context-manager stand-in for VisionSession (no model loads)."""

    def __init__(self, settings) -> None:  # noqa: ANN001
        self._settings = settings

    async def __aenter__(self) -> _FakeVisionSession:
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


def _vision_settings() -> Settings:
    settings = _disabled_settings()
    settings.vision.enabled = True
    return settings


async def test_vision_disabled_by_default_is_noop():
    settings = _disabled_settings()
    assert settings.vision.enabled is False
    container = build_container(settings)
    orch = ReconOrchestrator(container)

    bundle = await orch.run(EngagementContext(target="example.com"))

    assert bundle.plan is not None and len(bundle.plan.tasks) == 3
    assert not any(a.type == AssetType.SCREENSHOT for a in bundle.assets)
    assert not any(a.type == AssetType.VISUAL_ELEMENT for a in bundle.assets)


async def test_vision_enabled_stubbed_produces_assets_and_findings(monkeypatch):
    monkeypatch.setattr("recon_platform.agents.vision.vision_available", lambda: True)
    monkeypatch.setattr("recon_platform.agents.vision.VisionSession", _FakeVisionSession)
    monkeypatch.setattr(
        "recon_platform.agents.vision.build_vision_modules",
        lambda: [_StubVisionModule()],
    )

    container = build_container(_vision_settings())
    orch = ReconOrchestrator(container)

    bundle = await orch.run(EngagementContext(target="example.com"))

    # Vision assets reached the knowledge graph.
    assert any(a.type == AssetType.SCREENSHOT for a in bundle.assets)
    assert any(a.type == AssetType.VISUAL_ELEMENT for a in bundle.assets)

    titles = [f.title.lower() for f in bundle.findings]
    assert any("secrets visible" in t for t in titles)
    assert any("sensitive page" in t for t in titles)
    assert any("login page without visible mfa" in t for t in titles)
    assert any("visual analysis" in t for t in titles)

    # The report renders a Visual Intelligence section.
    from recon_platform.reporting.renderers import get_renderer

    md = get_renderer("markdown").render(bundle)
    assert "Visual Intelligence" in md

    assert bundle.plan is not None and len(bundle.plan.tasks) == 3


async def test_vision_graceful_degradation_when_backend_missing(monkeypatch):
    monkeypatch.setattr("recon_platform.agents.vision.vision_available", lambda: False)

    container = build_container(_vision_settings())
    orch = ReconOrchestrator(container)

    bundle = await orch.run(EngagementContext(target="example.com"))

    skips = [
        t for t in bundle.traces if t.agent == AgentRole.VISION and t.action == "skip"
    ]
    assert skips, "expected a vision skip trace"
    assert not any(a.type == AssetType.SCREENSHOT for a in bundle.assets)
