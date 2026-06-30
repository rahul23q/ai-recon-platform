"""Concrete desktop modules + the default ordered module set.

Mirrors :mod:`recon_platform.vision.modules`. Each module observes or interacts
with the desktop through the session and emits assets/relations, degrading
gracefully — any error is captured in ``result.errors`` so the pipeline always
completes.

The default set is read-only first (window discovery, screen capture, clipboard
read), then the gated interaction module that clicks Vision-detected elements. In
the platform's safe posture (``allow_input=False``) the interaction module still
*plans* and records its clicks without sending real input, so the run is fully
auditable offline.
"""

from __future__ import annotations

from pathlib import Path

import anyio

from recon_platform.desktop.base import DesktopContext, DesktopModule
from recon_platform.domain.enums import AssetType, RelationType, ToolPermission
from recon_platform.domain.schemas import Asset, ReconResult, Relation

#: Cache key under which the agent injects Vision-detected on-screen elements
#: (a list of ``{"key", "label", "box", "confidence", "screenshot"}`` dicts).
UI_ELEMENTS_KEY = "ui_elements"


def _slug(target: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "-._" else "_" for ch in target) or "target"


def _action_asset(action, source: str) -> Asset:  # noqa: ANN001 - DesktopAction
    """Turn a recorded DesktopAction into a DESKTOP_ACTION asset."""
    data = action.as_dict()
    attrs = {"action_type": action.kind, "via": "desktop"}
    for k, v in data.items():
        if k in ("kind",):
            continue
        attrs[k] = str(v) if v is not None else ""
    return Asset(
        type=AssetType.DESKTOP_ACTION,
        value=f"{action.kind}:{action.detail}",
        source=source,
        attributes=attrs,
        confidence=0.9 if action.performed else 0.5,
    )


class WindowDiscoveryModule(DesktopModule):
    name = "window_discovery"
    description = "Enumerate open OS windows and their geometry."

    async def run(self, ctx: DesktopContext) -> ReconResult:
        result = ReconResult(task_id="", module=self.name)
        try:
            windows = ctx.session.discover_windows()
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"window discovery failed: {exc}")
            return result
        for w in windows:
            attrs = {"handle": w.handle, "active": w.is_active, "via": "desktop"}
            if w.region is not None:
                attrs["box"] = w.region.as_dict()
            result.assets.append(
                Asset(type=AssetType.WINDOW, value=w.title, source=self.name, attributes=attrs)
            )
        result.notes.append(f"Discovered {len(result.assets)} window(s).")
        return result


class ScreenCaptureModule(DesktopModule):
    name = "screen_capture"
    description = "Capture a screenshot of the desktop as evidence."

    async def run(self, ctx: DesktopContext) -> ReconResult:
        result = ReconResult(task_id="", module=self.name)
        if not ctx.settings.desktop.screenshot:
            result.notes.append("Screen capture disabled (settings.desktop.screenshot=False).")
            return result

        directory = Path(ctx.settings.desktop.screenshot_dir)
        await anyio.to_thread.run_sync(lambda: directory.mkdir(parents=True, exist_ok=True))
        out_path = str(directory / f"{_slug(ctx.target)}.desktop.png")

        action = ctx.session.capture_screen(out_path)
        if action.performed and action.attributes.get("path"):
            path = action.attributes["path"]
            result.assets.append(
                Asset(
                    type=AssetType.SCREENSHOT,
                    value=path,
                    source=self.name,
                    attributes={"via": "desktop", "path": path},
                )
            )
            result.notes.append(f"Captured desktop screenshot to {path}.")
        else:
            result.notes.append("No screen-capture backend available; skipped.")
        return result


class ClipboardModule(DesktopModule):
    name = "clipboard"
    description = "Inspect the current clipboard contents."

    async def run(self, ctx: DesktopContext) -> ReconResult:
        result = ReconResult(task_id="", module=self.name)
        action = ctx.session.read_clipboard()
        length = int(action.attributes.get("length", "0") or "0")
        if length:
            result.assets.append(_action_asset(action, self.name))
            result.notes.append(f"Read {length} char(s) from clipboard.")
        else:
            result.notes.append("Clipboard empty or unavailable.")
        return result


class UIInteractionModule(DesktopModule):
    """Plan/perform clicks on Vision-detected on-screen elements ("click by sight").

    Reads the elements the agent injected into ``ctx._cache[UI_ELEMENTS_KEY]``
    (``VISUAL_ELEMENT`` assets carrying a bounding box) and clicks the centre of
    each above the configured confidence. Every click is recorded as a
    ``DESKTOP_ACTION`` asset and linked back to the element it acted on; in safe
    mode the clicks are planned (dry-run) rather than sent.
    """

    name = "ui_interaction"
    description = "Interact with Vision-detected UI elements (gated by allow_input)."
    permissions = (ToolPermission.FILESYSTEM_WRITE, ToolPermission.DESKTOP)

    async def run(self, ctx: DesktopContext) -> ReconResult:
        result = ReconResult(task_id="", module=self.name)
        elements = ctx._cache.get(UI_ELEMENTS_KEY, [])
        if not elements:
            result.notes.append("No Vision-detected UI elements to interact with.")
            return result

        threshold = ctx.settings.desktop.min_element_confidence
        budget = ctx.settings.desktop.max_actions
        acted = 0
        for el in elements:
            if acted >= budget:
                break
            box = el.get("box")
            if not box:
                continue
            if float(el.get("confidence", 0.0)) < threshold:
                continue
            label = el.get("label", "element")
            action = ctx.session.click_element(box, label=f"click {label}")
            acted += 1
            asset = _action_asset(action, self.name)
            asset.attributes["element"] = str(label)
            result.assets.append(asset)
            target_key = el.get("key")
            if target_key:
                result.relations.append(
                    Relation(
                        source_key=asset.key,
                        target_key=target_key,
                        type=RelationType.REFERENCES,
                        attributes={"interaction": "click"},
                    )
                )

        mode = "performed" if ctx.session.input_allowed else "planned (dry-run)"
        result.notes.append(f"{mode} {acted} click(s) on detected element(s).")
        return result


def build_desktop_modules() -> list[DesktopModule]:
    """Return the ordered default desktop module set.

    Observation runs first (windows, screen capture, clipboard); the gated
    interaction module runs last so it can act on what was perceived.
    """
    return [
        WindowDiscoveryModule(),
        ScreenCaptureModule(),
        ClipboardModule(),
        UIInteractionModule(),
    ]


#: Convenience list of module classes for discovery/registries.
DESKTOP_MODULES = [
    WindowDiscoveryModule,
    ScreenCaptureModule,
    ClipboardModule,
    UIInteractionModule,
]
