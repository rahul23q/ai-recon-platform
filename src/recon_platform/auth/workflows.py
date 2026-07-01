"""Concrete authentication workflows + the ``build_workflows`` factory.

Each workflow drives an :class:`~recon_platform.auth.page.AuthPage` through one
authentication flow and returns an :class:`~recon_platform.auth.models.AuthResult`.
The workflows contain no Playwright: they call the narrow ``AuthPage`` seam and
the pure :mod:`recon_platform.auth.forms` heuristics, so they run identically
against the real browser and the test fake. All page I/O is wrapped so a failure
becomes ``AuthResult.error`` rather than an exception.
"""

from __future__ import annotations

import abc
from urllib.parse import urlsplit

from recon_platform.auth.credentials import Credentials
from recon_platform.auth.forms import locate_fields, login_succeeded
from recon_platform.auth.models import AuthResult, CapturedSession
from recon_platform.auth.page import AuthPage
from recon_platform.core.config import Settings


def _scheme(url: str) -> str:
    return urlsplit(url).scheme.lower()


def _cookie_names(cookies: list[dict]) -> list[str]:
    return sorted({str(c.get("name", "")) for c in cookies if c.get("name")})


class AuthWorkflow(abc.ABC):
    """Abstract base for one authentication flow."""

    name: str = "workflow"

    @abc.abstractmethod
    async def run(
        self, page: AuthPage, creds: Credentials, urls: list[str], settings: Settings
    ) -> list[AuthResult]:
        raise NotImplementedError


class LoginWorkflow(AuthWorkflow):
    """Attempt to log in at each candidate URL and capture the session."""

    name = "login"

    async def run(self, page, creds, urls, settings):  # noqa: ANN001
        results: list[AuthResult] = []
        if not creds.has_login:
            return [AuthResult(workflow=self.name, reason="no credentials configured")]
        for url in urls:
            results.append(await self._attempt(page, creds, url))
            if results[-1].success:
                break  # first successful login is enough
        return results

    async def _attempt(self, page: AuthPage, creds: Credentials, url: str) -> AuthResult:
        result = AuthResult(workflow=self.name, url=url, scheme=_scheme(url))
        try:
            await page.goto(url)
            fmap = locate_fields(await page.fields())
            if not fmap.has_password:
                result.reason = "no login form found"
                return result
            before_url = await page.current_url()
            before_cookies = _cookie_names(await page.cookies())

            identity_selector = fmap.username or fmap.email
            identity_value = creds.username or creds.email
            if identity_selector and identity_value:
                await page.fill(identity_selector, identity_value)
            await page.fill(fmap.password, creds.password)
            await page.submit(fmap.submit)

            after_url = await page.current_url()
            after_cookies_full = await page.cookies()
            after_cookies = _cookie_names(after_cookies_full)
            remaining = locate_fields(await page.fields())

            ok, reason = login_succeeded(
                before_url=before_url,
                after_url=after_url,
                cookie_names_before=before_cookies,
                cookie_names_after=after_cookies,
                form_present_after=remaining.has_password,
                page_text_after=await page.content(),
            )
            result.success = ok
            result.reason = reason
            if ok:
                result.session = CapturedSession(
                    workflow=self.name, url=after_url or url, cookies=after_cookies_full
                )
        except Exception as exc:  # noqa: BLE001 - resilience contract
            result.error = str(exc)
            result.reason = "workflow error"
        return result


class RegistrationWorkflow(AuthWorkflow):
    """Attempt to register a new account at each candidate URL."""

    name = "registration"

    async def run(self, page, creds, urls, settings):  # noqa: ANN001
        results: list[AuthResult] = []
        if not creds.has_registration:
            return [AuthResult(workflow=self.name, reason="no email/password configured")]
        for url in urls:
            results.append(await self._attempt(page, creds, url))
            if results[-1].success:
                break
        return results

    async def _attempt(self, page: AuthPage, creds: Credentials, url: str) -> AuthResult:
        result = AuthResult(workflow=self.name, url=url, scheme=_scheme(url))
        try:
            await page.goto(url)
            fmap = locate_fields(await page.fields())
            if not fmap.has_password or not (fmap.email or fmap.username):
                result.reason = "no registration form found"
                return result
            before_cookies = _cookie_names(await page.cookies())
            if fmap.email:
                await page.fill(fmap.email, creds.email)
            if fmap.username and creds.username:
                await page.fill(fmap.username, creds.username)
            await page.fill(fmap.password, creds.password)
            if fmap.password_confirm:
                await page.fill(fmap.password_confirm, creds.password)
            await page.submit(fmap.submit)

            after_cookies_full = await page.cookies()
            after_cookies = _cookie_names(after_cookies_full)
            remaining = locate_fields(await page.fields())
            ok = (not remaining.has_password) or after_cookies != before_cookies
            result.success = ok
            result.reason = "registration submitted" if ok else "registration form still present"
            if ok:
                result.session = CapturedSession(
                    workflow=self.name, url=url, cookies=after_cookies_full
                )
        except Exception as exc:  # noqa: BLE001 - resilience contract
            result.error = str(exc)
            result.reason = "workflow error"
        return result


class ForgotPasswordWorkflow(AuthWorkflow):
    """Submit the account email to a forgot-password form."""

    name = "forgot_password"

    async def run(self, page, creds, urls, settings):  # noqa: ANN001
        email = creds.email or creds.username
        if not email:
            return [AuthResult(workflow=self.name, reason="no email configured")]
        results: list[AuthResult] = []
        for url in urls:
            results.append(await self._attempt(page, email, url))
            if results[-1].success:
                break
        return results

    async def _attempt(self, page: AuthPage, email: str, url: str) -> AuthResult:
        result = AuthResult(workflow=self.name, url=url, scheme=_scheme(url))
        try:
            await page.goto(url)
            fmap = locate_fields(await page.fields())
            target = fmap.email or fmap.username
            if not target:
                result.reason = "no forgot-password form found"
                return result
            await page.fill(target, email)
            await page.submit(fmap.submit)
            result.success = True
            result.reason = "reset request submitted"
        except Exception as exc:  # noqa: BLE001 - resilience contract
            result.error = str(exc)
            result.reason = "workflow error"
        return result


class AdminProbeWorkflow(AuthWorkflow):
    """Probe admin URLs to see whether they are reachable without authentication."""

    name = "admin_probe"

    async def run(self, page, creds, urls, settings):  # noqa: ANN001
        results: list[AuthResult] = []
        for url in urls:
            results.append(await self._attempt(page, url))
        return results

    async def _attempt(self, page: AuthPage, url: str) -> AuthResult:
        result = AuthResult(workflow=self.name, url=url, scheme=_scheme(url))
        try:
            await page.goto(url)
            fmap = locate_fields(await page.fields())
            after_url = await page.current_url()
            # If a login form is presented (or we were redirected to a login URL),
            # the panel is gated; otherwise it appears reachable unauthenticated.
            redirected_to_login = "login" in (after_url or "").lower()
            gated = fmap.has_password or redirected_to_login
            accessible = not gated
            result.success = accessible
            result.detail = {"accessible_unauthenticated": accessible}
            result.reason = (
                "admin panel reachable without authentication"
                if accessible
                else "admin panel gated by authentication"
            )
        except Exception as exc:  # noqa: BLE001 - resilience contract
            result.error = str(exc)
            result.reason = "workflow error"
        return result


def build_workflows(settings: Settings | None = None) -> list[AuthWorkflow]:
    """Return the enabled workflows, honouring the per-workflow toggles."""
    auth = settings.auth if settings is not None else None
    flows: list[AuthWorkflow] = []
    if auth is None or auth.attempt_login:
        flows.append(LoginWorkflow())
    if auth is None or auth.attempt_registration:
        flows.append(RegistrationWorkflow())
    if auth is None or auth.attempt_forgot_password:
        flows.append(ForgotPasswordWorkflow())
    if auth is None or auth.probe_admin:
        flows.append(AdminProbeWorkflow())
    return flows
