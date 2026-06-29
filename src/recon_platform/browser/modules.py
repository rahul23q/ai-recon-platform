"""Concrete browser modules + the default ordered module set.

Mirrors :mod:`recon_platform.recon.modules`. Each module observes a live,
navigated page and returns assets/relations, degrading gracefully — any I/O or
DOM error is captured in ``result.errors`` so the pipeline always completes.

Order matters: :class:`NavigationModule` runs first (it performs the navigation
and stashes the final URL in the shared ``_cache``); the other modules read the
already-loaded page, the session's captured network traffic, and its cookies.

Asset shapes deliberately match the Phase-1 conventions so existing Analysis
rules apply unchanged: ``HEADER`` assets carry ``{"name","value"}`` attributes,
and ``ENDPOINT``/``URL`` assets reuse the same types the passive modules emit.
"""

from __future__ import annotations

from urllib.parse import urlparse

from recon_platform.browser.base import BrowserContext, BrowserModule
from recon_platform.core.logging import get_logger
from recon_platform.domain.enums import AssetType, RelationType
from recon_platform.domain.schemas import Asset, ReconResult, Relation

log = get_logger(__name__)


def _same_origin(url: str, host: str) -> bool:
    """True when ``url``'s host equals ``host`` (ignoring leading ``www.``)."""
    try:
        netloc = urlparse(url).netloc.lower().split("@")[-1].split(":")[0]
    except Exception:  # noqa: BLE001
        return False
    return netloc == host.lower() or netloc == f"www.{host.lower()}"


class NavigationModule(BrowserModule):
    name = "navigation"
    description = "Navigate the home page in a real browser; capture URL, status, title."

    async def run(self, ctx: BrowserContext) -> ReconResult:
        result = ReconResult(task_id="", module=self.name)
        url = f"https://{ctx.target}/"
        try:
            response = await ctx.session.goto(url)
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"navigation to {url} failed: {exc}")
            return result

        final_url = getattr(ctx.page, "url", url) or url
        status = getattr(response, "status", None)
        try:
            title = await ctx.page.title()
        except Exception:  # noqa: BLE001
            title = ""

        attributes: dict[str, object] = {"title": title, "via": "browser"}
        if status is not None:
            attributes["status_code"] = status

        # Screenshot evidence (best-effort; path recorded on the asset).
        if ctx.settings.browser.screenshot:
            import pathlib

            import anyio

            safe = ctx.target.replace(":", "_").replace("/", "_")
            directory = pathlib.Path(ctx.settings.browser.screenshot_dir)
            # Offload the sync filesystem call so the event loop never blocks.
            await anyio.to_thread.run_sync(
                lambda: directory.mkdir(parents=True, exist_ok=True)
            )
            shot_path = str(directory / f"{safe}.png")
            saved = await ctx.session.screenshot(shot_path)
            if saved:
                attributes["screenshot"] = saved

        url_asset = Asset(
            type=AssetType.URL,
            value=final_url,
            source=self.name,
            attributes=attributes,
        )
        result.assets.append(url_asset)
        result.relations.append(
            Relation(
                source_key=f"{AssetType.DOMAIN.value}:{ctx.target.lower()}",
                target_key=url_asset.key,
                type=RelationType.SERVES,
            )
        )
        ctx._cache["final_url"] = final_url
        ctx._cache["navigated"] = True
        note = f"Navigated to {final_url}"
        if status is not None:
            note += f" (HTTP {status})"
        if ctx.session.recovery_notes:
            result.notes.extend(ctx.session.recovery_notes)
        result.notes.append(note)
        return result


class NetworkCaptureModule(BrowserModule):
    name = "network_capture"
    description = "Record same-origin network requests and response headers from DevTools."

    async def run(self, ctx: BrowserContext) -> ReconResult:
        result = ReconResult(task_id="", module=self.name)
        if not ctx._cache.get("navigated"):
            result.notes.append("No navigation occurred; nothing to capture.")
            return result

        seen: set[str] = set()
        for req in getattr(ctx.session, "requests", []):
            if not _same_origin(req.url, ctx.target):
                continue
            if req.url in seen:
                continue
            seen.add(req.url)
            result.assets.append(
                Asset(
                    type=AssetType.ENDPOINT,
                    value=req.url,
                    source=self.name,
                    attributes={
                        "method": req.method,
                        "resource_type": req.resource_type,
                        "from": "browser-network",
                    },
                )
            )

        # Response headers of the main document → HEADER assets (Phase-1 shape).
        for name, value in getattr(ctx.session, "response_headers", {}).items():
            result.assets.append(
                Asset(
                    type=AssetType.HEADER,
                    value=f"{name}: {value}",
                    source=self.name,
                    attributes={"name": name.lower(), "value": value},
                )
            )

        result.notes.append(
            f"Captured {len(seen)} same-origin request(s) and "
            f"{len(getattr(ctx.session, 'response_headers', {}))} response header(s)."
        )
        return result


class CookieModule(BrowserModule):
    name = "cookies"
    description = "Inventory cookies set in the browser and flag missing security attributes."

    async def run(self, ctx: BrowserContext) -> ReconResult:
        result = ReconResult(task_id="", module=self.name)
        try:
            cookies = await ctx.session.cookies()
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"cookie read failed: {exc}")
            return result

        for c in cookies:
            name = str(c.get("name", ""))
            result.assets.append(
                Asset(
                    type=AssetType.COOKIE,
                    value=name,
                    source=self.name,
                    attributes={
                        "domain": c.get("domain", ""),
                        "secure": bool(c.get("secure", False)),
                        "http_only": bool(c.get("httpOnly", False)),
                        "same_site": c.get("sameSite", "None"),
                    },
                )
            )
        result.notes.append(f"Observed {len(cookies)} cookie(s).")
        return result


class ScriptInventoryModule(BrowserModule):
    name = "script_inventory"
    description = "Inventory <script src> URLs as JS_FILE assets (feeds JS analysis)."

    async def run(self, ctx: BrowserContext) -> ReconResult:
        result = ReconResult(task_id="", module=self.name)
        try:
            srcs = await ctx.page.eval_on_selector_all(
                "script[src]", "els => els.map(e => e.src)"
            )
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"script inventory failed: {exc}")
            return result

        for src in sorted({s for s in srcs if s}):
            result.assets.append(
                Asset(type=AssetType.JS_FILE, value=src, source=self.name)
            )
        result.notes.append(f"Inventoried {len(set(srcs))} script source(s).")
        return result


class DOMLinksModule(BrowserModule):
    name = "dom_links"
    description = "Extract same-origin links and form actions as ENDPOINT assets."

    async def run(self, ctx: BrowserContext) -> ReconResult:
        result = ReconResult(task_id="", module=self.name)
        try:
            hrefs = await ctx.page.eval_on_selector_all(
                "a[href]", "els => els.map(e => e.href)"
            )
            actions = await ctx.page.eval_on_selector_all(
                "form[action]", "els => els.map(e => e.action)"
            )
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"DOM link extraction failed: {exc}")
            return result

        targets = {u for u in (list(hrefs) + list(actions)) if u and _same_origin(u, ctx.target)}
        for url in sorted(targets):
            result.assets.append(
                Asset(
                    type=AssetType.ENDPOINT,
                    value=url,
                    source=self.name,
                    attributes={"from": "dom"},
                )
            )
        result.notes.append(f"Extracted {len(targets)} same-origin link(s)/form action(s).")
        return result


def build_browser_modules() -> list[BrowserModule]:
    """Return the ordered default browser module set.

    Order matters: ``navigation`` performs the navigation and populates the
    shared ``_cache`` that the later modules depend on.
    """
    return [
        NavigationModule(),
        NetworkCaptureModule(),
        CookieModule(),
        ScriptInventoryModule(),
        DOMLinksModule(),
    ]


#: Convenience list of module classes for discovery/registries.
BROWSER_MODULES = [
    NavigationModule,
    NetworkCaptureModule,
    CookieModule,
    ScriptInventoryModule,
    DOMLinksModule,
]
