"""Authentication-agent tests — hermetic (no browser; the page seam is faked).

Three layers, mirroring ``tests/test_active_recon.py``:

* **Pure heuristics** — ``auth.forms`` (field classification, form location,
  login-success detection), ``auth.discovery`` (candidate URLs), and
  ``auth.credentials`` (masking) exercised directly.
* **Workflows** — the concrete workflows run against a scripted ``FakeAuthPage``
  implementing the ``AuthPage`` protocol; no Playwright.
* **Pipeline** — the two-key gate (disabled / unauthorized / gate-fail skip) and a
  stubbed end-to-end run (``open_auth_page`` monkeypatched) proving SESSION assets
  reach the graph, credentials never leak, findings render, and the report section
  appears.
"""

from __future__ import annotations

import contextlib

import pytest

from recon_platform.auth.credentials import Credentials, mask
from recon_platform.auth.discovery import (
    candidate_admin_urls,
    candidate_login_urls,
)
from recon_platform.auth.forms import (
    FieldInfo,
    classify_field,
    locate_fields,
    login_succeeded,
)
from recon_platform.auth.workflows import (
    AdminProbeWorkflow,
    LoginWorkflow,
    build_workflows,
)
from recon_platform.bootstrap import build_container
from recon_platform.core.config import Settings
from recon_platform.domain.enums import AgentRole, AssetType
from recon_platform.domain.schemas import Asset, EngagementContext, ReconResult
from recon_platform.orchestration.graph import ReconOrchestrator
from recon_platform.recon.base import ReconModule


# ---------------------------------------------------------------------------
# Pure heuristics
# ---------------------------------------------------------------------------
def test_classify_field():
    assert classify_field(FieldInfo(field_type="password")) == "password"
    assert classify_field(FieldInfo(name="email", field_type="text")) == "email"
    assert classify_field(FieldInfo(name="username", field_type="text")) == "username"
    assert classify_field(FieldInfo(field_type="submit")) == "submit"
    assert classify_field(FieldInfo(name="q", field_type="text")) == "other"


def test_locate_fields_login_and_register():
    login = locate_fields(
        [
            FieldInfo(name="username", field_type="text"),
            FieldInfo(name="password", field_type="password"),
        ]
    )
    assert login.username == '[name="username"]' and login.password == '[name="password"]'
    reg = locate_fields(
        [
            FieldInfo(name="email", field_type="email"),
            FieldInfo(name="password", field_type="password"),
            FieldInfo(name="confirm", field_type="password"),
        ]
    )
    assert reg.email and reg.password and reg.password_confirm


def test_login_succeeded_signals():
    ok, _ = login_succeeded(
        before_url="https://x/login", after_url="https://x/login",
        cookie_names_before=[], cookie_names_after=["sessionid"], form_present_after=True,
    )
    assert ok is True  # new session cookie
    bad, _ = login_succeeded(
        before_url="https://x/login", after_url="https://x/login",
        cookie_names_before=[], cookie_names_after=[], form_present_after=True,
        page_text_after="Invalid username or password",
    )
    assert bad is False
    nav, _ = login_succeeded(
        before_url="https://x/login", after_url="https://x/dashboard",
        cookie_names_before=[], cookie_names_after=[], form_present_after=False,
    )
    assert nav is True


def test_discovery_candidates():
    assets = [
        Asset(type=AssetType.URL, value="https://x.com/login", source="s"),
        Asset(type=AssetType.URL, value="https://x.com/admin", source="s"),
        Asset(type=AssetType.URL, value="https://x.com/about", source="s"),
    ]
    assert candidate_login_urls(assets) == ["https://x.com/login"]
    assert candidate_admin_urls(assets) == ["https://x.com/admin"]


def test_credentials_masking():
    assert mask("secret") == "s•••••"
    assert mask("") == "—"
    creds = Credentials(username="admin", password="pw")
    assert creds.has_login is True
    assert creds.masked()["password"] == "p•"


# ---------------------------------------------------------------------------
# Workflows over a fake page
# ---------------------------------------------------------------------------
class FakeAuthPage:
    """Scripted `AuthPage`: a login form that sets a session cookie on submit."""

    def __init__(self, *, fields, cookies_after=None, url_after=None, form_after=False):
        self._fields = fields
        self._cookies: list[dict] = []
        self._cookies_after = cookies_after or []
        self._url = "https://x.com/login"
        self._url_after = url_after
        self._submitted = False
        self._form_after = form_after
        self.filled: dict[str, str] = {}

    async def goto(self, url):
        self._url = url

    async def fields(self):
        if self._submitted and not self._form_after:
            return []
        return list(self._fields)

    async def fill(self, selector, value):
        self.filled[selector] = value

    async def submit(self, selector):
        self._submitted = True
        self._cookies = list(self._cookies_after)
        if self._url_after:
            self._url = self._url_after

    async def current_url(self):
        return self._url

    async def cookies(self):
        return list(self._cookies)

    async def content(self):
        return ""


async def test_login_workflow_captures_session():
    page = FakeAuthPage(
        fields=[
            FieldInfo(name="username", field_type="text"),
            FieldInfo(name="password", field_type="password"),
            FieldInfo(field_type="submit"),
        ],
        cookies_after=[{"name": "sessionid", "value": "abc123"}],
    )
    creds = Credentials(username="admin", password="pw")
    results = await LoginWorkflow().run(page, creds, ["https://x.com/login"], Settings())
    assert results[0].success is True
    assert results[0].session is not None
    assert results[0].session.cookie_names == ["sessionid"]
    # The password was filled but is not on the result.
    assert page.filled['[name="password"]'] == "pw"


async def test_login_workflow_without_credentials_notes():
    results = await LoginWorkflow().run(FakeAuthPage(fields=[]), Credentials(), [], Settings())
    assert results[0].success is False and "no credentials" in results[0].reason


async def test_admin_probe_flags_open_panel():
    page = FakeAuthPage(fields=[], url_after="https://x.com/admin")  # no login form
    results = await AdminProbeWorkflow().run(
        page, Credentials(), ["https://x.com/admin"], Settings()
    )
    assert results[0].success is True
    assert results[0].detail["accessible_unauthenticated"] is True


def test_build_workflows_honours_toggles():
    settings = Settings()
    settings.auth.attempt_registration = True
    names = {w.name for w in build_workflows(settings)}
    assert {"login", "admin_probe", "registration"} <= names


# ---------------------------------------------------------------------------
# Pipeline — two-key gate + stubbed end-to-end run
# ---------------------------------------------------------------------------
class _StubReconModule(ReconModule):
    name = "stub"
    description = "offline stub"

    async def run(self, ctx) -> ReconResult:  # noqa: ANN001
        return ReconResult(
            task_id="",
            module=self.name,
            assets=[
                Asset(type=AssetType.DOMAIN, value=ctx.target, source="stub"),
                Asset(type=AssetType.URL, value="https://example.com/login", source="stub"),
                Asset(type=AssetType.URL, value="https://example.com/admin", source="stub"),
            ],
            notes=["stub ran"],
        )


@pytest.fixture(autouse=True)
def _patch_recon_modules(monkeypatch):
    factory = lambda: [_StubReconModule()]  # noqa: E731
    monkeypatch.setattr("recon_platform.agents.recon.build_passive_modules", factory)
    monkeypatch.setattr("recon_platform.agents.planner.build_passive_modules", factory)


def _base_settings() -> Settings:
    settings = Settings(authorized_only=False)
    settings.llm.enabled = False
    return settings


async def test_auth_disabled_by_default_is_noop():
    settings = _base_settings()
    assert settings.auth.enabled is False
    bundle = await ReconOrchestrator(build_container(settings)).run(
        EngagementContext(target="example.com")
    )
    assert not any(a.type == AssetType.SESSION for a in bundle.assets)
    assert not any(t.agent == AgentRole.AUTHENTICATION for t in bundle.traces)


async def test_auth_enabled_but_unauthorized_skips():
    settings = _base_settings()
    settings.auth.enabled = True
    settings.auth.authorized = False  # second key withheld
    bundle = await ReconOrchestrator(build_container(settings)).run(
        EngagementContext(target="example.com")
    )
    skips = [
        t for t in bundle.traces
        if t.agent == AgentRole.AUTHENTICATION and t.action == "skip"
    ]
    assert skips and "not authorized" in skips[0].observation


async def test_auth_two_keys_runs_and_reports(monkeypatch):
    login_page = FakeAuthPage(
        fields=[
            FieldInfo(name="username", field_type="text"),
            FieldInfo(name="password", field_type="password"),
            FieldInfo(field_type="submit"),
        ],
        cookies_after=[{"name": "sessionid", "value": "s3cr3t"}],
    )

    @contextlib.asynccontextmanager
    async def _fake_open(settings):  # noqa: ANN001
        yield login_page

    monkeypatch.setattr("recon_platform.agents.auth.open_auth_page", _fake_open)

    settings = _base_settings()
    settings.auth.enabled = True
    settings.auth.authorized = True
    settings.auth.username = "admin"
    settings.auth.password = __import__("pydantic").SecretStr("hunter2")

    bundle = await ReconOrchestrator(build_container(settings)).run(
        EngagementContext(target="example.com")
    )

    sessions = [a for a in bundle.assets if a.type == AssetType.SESSION]
    assert sessions and any(s.attributes.get("success") for s in sessions)
    # Credentials must never appear anywhere in the rendered report.
    from recon_platform.reporting.renderers import get_renderer

    md = get_renderer("markdown").render(bundle)
    assert "Authentication" in md
    assert "hunter2" not in md and "s3cr3t" not in md
    assert any("authentication workflows attempted" in f.title.lower() for f in bundle.findings)
