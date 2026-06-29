"""BrowserSession — the Playwright lifecycle wrapper.

An async context manager that launches a Chromium browser, navigates with
**retry + restart on crash** (self-healing groundwork, recorded as a
``recovery_plan`` in reasoning traces), captures network requests / response
headers via page events, exposes cookies, and writes screenshot evidence.

Playwright is imported **lazily** here and nowhere else, so the rest of the
platform imports and runs without the optional ``browser`` extra installed. When
Playwright is missing or the browser is disabled, callers consult
:func:`playwright_available` and skip cleanly — exactly the degradation pattern
the LangGraph / LLM layers use.
"""

from __future__ import annotations

from types import TracebackType
from typing import Any

from recon_platform.core.config import Settings
from recon_platform.core.logging import get_logger

log = get_logger(__name__)


def playwright_available() -> bool:
    """True when the optional Playwright dependency can be imported.

    Mirrors ``ReconOrchestrator._langgraph_available`` — a cheap lazy-import
    probe so callers degrade gracefully when the ``browser`` extra is absent.
    """
    try:
        import playwright.async_api  # noqa: F401
    except Exception:  # noqa: BLE001 - any import-time failure means "unavailable"
        return False
    return True


class CapturedRequest:
    """A lightweight record of one network request observed by the page."""

    __slots__ = ("url", "method", "resource_type", "status", "headers")

    def __init__(
        self,
        url: str,
        method: str,
        resource_type: str,
        status: int | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.url = url
        self.method = method
        self.resource_type = resource_type
        self.status = status
        self.headers = headers or {}


class BrowserSession:
    """Async context manager around the Playwright browser lifecycle.

    Usage::

        async with BrowserSession(settings) as session:
            await session.goto("https://example.com/")
            await session.screenshot(path)
            cookies = await session.cookies()

    All methods are resilient; ``goto`` retries and restarts the browser once on
    a crash before giving up. The session records every request it observes in
    ``self.requests`` and the final response headers in ``self.response_headers``.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._pw: Any = None
        self._browser: Any = None
        self._context: Any = None
        self.page: Any = None
        #: Network requests observed during the session (same-origin filtering is
        #: left to the modules so the raw capture stays complete).
        self.requests: list[CapturedRequest] = []
        #: Response headers of the main navigated document.
        self.response_headers: dict[str, str] = {}
        #: Recovery actions taken (surfaced into reasoning traces).
        self.recovery_notes: list[str] = []

    # -- lifecycle ----------------------------------------------------------
    async def __aenter__(self) -> BrowserSession:
        await self.launch()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.close()

    async def launch(self) -> None:
        """Start Playwright + a Chromium browser context with a page.

        Imports Playwright lazily; raises only if the extra is genuinely missing
        (callers gate on :func:`playwright_available` first).
        """
        from playwright.async_api import async_playwright

        bs = self._settings.browser
        self._pw = await async_playwright().start()
        engine = getattr(self._pw, bs.engine, self._pw.chromium)
        self._browser = await engine.launch(headless=bs.headless)
        self._context = await self._browser.new_context(
            user_agent=self._settings.http.user_agent,
            ignore_https_errors=not self._settings.http.verify_tls,
        )
        self.page = await self._context.new_page()
        self._wire_capture(self.page)
        log.info("browser.launched", engine=bs.engine, headless=bs.headless)

    def _wire_capture(self, page: Any) -> None:
        """Subscribe to page events to capture network traffic."""

        def _on_request(request: Any) -> None:
            try:
                self.requests.append(
                    CapturedRequest(
                        url=request.url,
                        method=request.method,
                        resource_type=request.resource_type,
                    )
                )
            except Exception:  # noqa: BLE001 - capture must never break navigation
                pass

        page.on("request", _on_request)

    async def goto(self, url: str) -> Any:
        """Navigate to ``url`` with one retry + browser restart on crash.

        Returns the Playwright ``Response`` (or ``None`` if the navigation
        produced no response). The restart is the seed of Phase-15 self-healing;
        the action is appended to ``self.recovery_notes`` so the agent can record
        it as a ``recovery_plan``.
        """
        timeout_ms = int(self._settings.browser.nav_timeout_seconds * 1000)
        try:
            return await self._navigate(url, timeout_ms)
        except Exception as first_exc:  # noqa: BLE001
            self.recovery_notes.append(
                f"navigation to {url} failed ({first_exc}); restarting browser and retrying"
            )
            log.warning("browser.goto.retry", url=url, error=str(first_exc))
            await self._restart()
            return await self._navigate(url, timeout_ms)

    async def _navigate(self, url: str, timeout_ms: int) -> Any:
        response = await self.page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
        if response is not None:
            try:
                self.response_headers = {k.lower(): v for k, v in response.headers.items()}
                # Backfill the matching captured request's status/headers.
                for req in self.requests:
                    if req.url == response.url:
                        req.status = response.status
                        req.headers = self.response_headers
            except Exception:  # noqa: BLE001
                pass
        return response

    async def _restart(self) -> None:
        """Tear down and relaunch the browser (preserving captured state)."""
        await self.close()
        await self.launch()

    async def screenshot(self, path: str) -> str | None:
        """Capture a full-page screenshot to ``path``; return the path or None."""
        if self.page is None:
            return None
        try:
            await self.page.screenshot(path=path, full_page=True)
            return path
        except Exception as exc:  # noqa: BLE001
            log.warning("browser.screenshot.failed", path=path, error=str(exc))
            return None

    async def cookies(self) -> list[dict[str, Any]]:
        """Return cookies set in the browser context."""
        if self._context is None:
            return []
        try:
            return await self._context.cookies()
        except Exception:  # noqa: BLE001
            return []

    async def close(self) -> None:
        """Best-effort teardown of every Playwright resource."""
        for closer in (
            getattr(self._context, "close", None),
            getattr(self._browser, "close", None),
            getattr(self._pw, "stop", None),
        ):
            if closer is None:
                continue
            try:
                await closer()
            except Exception:  # noqa: BLE001
                pass
        self._context = self._browser = self._pw = self.page = None
