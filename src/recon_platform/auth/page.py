"""The ``AuthPage`` seam — the minimal browser operations the workflows need.

Keeping the workflows behind this narrow ``Protocol`` means the authentication
logic never imports Playwright and is fully testable with a fake page. The
Playwright-backed :class:`PlaywrightAuthPage` wraps a
:class:`~recon_platform.browser.session.BrowserSession`, and :func:`open_auth_page`
is the async-context-manager factory the agent uses (and the tests monkeypatch).
"""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator
from typing import Any, Protocol, runtime_checkable

from recon_platform.auth.forms import FieldInfo
from recon_platform.core.config import Settings
from recon_platform.core.logging import get_logger

log = get_logger(__name__)

# JS to scrape input/button descriptors from the live page in one round-trip.
_FIELD_SCRAPE_JS = """
() => Array.from(document.querySelectorAll('input,button,select,textarea')).map(e => ({
    name: e.name || '',
    field_type: (e.getAttribute('type') || e.tagName || '').toLowerCase(),
    field_id: e.id || '',
    placeholder: e.getAttribute('placeholder') || '',
    autocomplete: e.getAttribute('autocomplete') || '',
}))
"""


@runtime_checkable
class AuthPage(Protocol):
    """The browser operations an auth workflow needs (implemented for real + fake)."""

    async def goto(self, url: str) -> None: ...
    async def fields(self) -> list[FieldInfo]: ...
    async def fill(self, selector: str, value: str) -> None: ...
    async def submit(self, selector: str | None) -> None: ...
    async def current_url(self) -> str: ...
    async def cookies(self) -> list[dict]: ...
    async def content(self) -> str: ...


class PlaywrightAuthPage:
    """`AuthPage` backed by a live :class:`BrowserSession` (Playwright)."""

    def __init__(self, session: Any) -> None:
        self._session = session

    async def goto(self, url: str) -> None:
        await self._session.goto(url)

    async def fields(self) -> list[FieldInfo]:
        page = self._session.page
        if page is None:
            return []
        try:
            raw = await page.evaluate(_FIELD_SCRAPE_JS)
        except Exception as exc:  # noqa: BLE001 - never break the workflow
            log.info("auth.fields.error", error=str(exc))
            return []
        return [FieldInfo(**{k: str(v) for k, v in item.items()}) for item in raw or []]

    async def fill(self, selector: str, value: str) -> None:
        page = self._session.page
        if page is not None:
            await page.fill(selector, value)

    async def submit(self, selector: str | None) -> None:
        page = self._session.page
        if page is None:
            return
        if selector:
            await page.click(selector)
        else:
            # No explicit submit control: press Enter in the password field.
            with contextlib.suppress(Exception):
                await page.keyboard.press("Enter")

    async def current_url(self) -> str:
        page = self._session.page
        return getattr(page, "url", "") if page is not None else ""

    async def cookies(self) -> list[dict]:
        return await self._session.cookies()

    async def content(self) -> str:
        page = self._session.page
        if page is None:
            return ""
        try:
            return await page.content()
        except Exception:  # noqa: BLE001
            return ""


@contextlib.asynccontextmanager
async def open_auth_page(settings: Settings) -> AsyncIterator[AuthPage | None]:
    """Yield a live :class:`AuthPage`, or ``None`` when the browser is unavailable.

    The agent gates on the yielded value: ``None`` ⇒ record a clean skip. Tests
    monkeypatch this function to yield a fake page, so the agent's flow is
    exercised without Playwright.
    """
    from recon_platform.browser.session import BrowserSession, playwright_available

    if not playwright_available():
        yield None
        return
    async with BrowserSession(settings) as session:
        yield PlaywrightAuthPage(session)
