"""Concrete vision modules + the default ordered module set.

Mirrors :mod:`recon_platform.browser.modules`. Each module observes the cached
per-screenshot :class:`~recon_platform.vision.models.VisionAnalysis` and emits
assets/relations, degrading gracefully — any error is captured in
``result.errors`` so the pipeline always completes.

Order matters: :class:`ScreenshotIngestModule` runs first — it creates the
``SCREENSHOT`` assets and runs OCR + detection once per image, stashing the
result in the shared ``_cache``; the later modules (OCR text, object detection,
QR codes) read that cache instead of re-running the models.
"""

from __future__ import annotations

from pathlib import Path, PurePath

import anyio

from recon_platform.domain.enums import AssetType, RelationType
from recon_platform.domain.schemas import Asset, ReconResult, Relation
from recon_platform.vision.base import VisionContext, VisionModule
from recon_platform.vision.detector import (
    extract_emails,
    extract_internal_urls,
    extract_phones,
    extract_urls,
    find_secrets,
)

#: Cache key under which ScreenshotIngestModule stores {path: VisionAnalysis}.
_ANALYSIS_KEY = "analysis"


def _basename(path: str) -> str:
    return PurePath(path).name or path


class ScreenshotIngestModule(VisionModule):
    name = "screenshot_ingest"
    description = "Ingest browser screenshots, run OCR + detection, classify the page."

    async def run(self, ctx: VisionContext) -> ReconResult:
        result = ReconResult(task_id="", module=self.name)
        screenshots = ctx.screenshots[: ctx.settings.vision.max_screenshots]
        if not screenshots:
            result.notes.append("No screenshots available to analyze.")
            return result

        analyses: dict[str, object] = {}
        url_map: dict[str, str] = ctx._cache.get("screenshot_urls", {})
        for path in screenshots:
            try:
                analysis = await ctx.session.analyze(path)
            except Exception as exc:  # noqa: BLE001
                result.errors.append(f"analysis of {path} failed: {exc}")
                continue
            analyses[path] = analysis

            attributes = {
                "path": path,
                "page_type": analysis.classification.page_type,
                "page_confidence": analysis.classification.confidence,
                "page_signals": ", ".join(analysis.classification.signals),
                "elements": len(analysis.objects),
                "ocr_provider": analysis.ocr.provider,
                "width": analysis.width,
                "height": analysis.height,
                "via": "vision",
            }
            # Optional annotated copy with bounding boxes (best-effort).
            if ctx.settings.vision.annotate:
                directory = Path(ctx.settings.vision.annotate_dir)
                # Offload the sync filesystem call so the event loop never blocks.
                await anyio.to_thread.run_sync(
                    lambda d=directory: d.mkdir(parents=True, exist_ok=True)
                )
                out_path = str(directory / f"{_basename(path)}.boxes.png")
                annotated = await ctx.session.annotate(path, analysis.objects, out_path)
                if annotated:
                    attributes["annotated"] = annotated

            shot = Asset(
                type=AssetType.SCREENSHOT,
                value=path,
                source=self.name,
                attributes=attributes,
            )
            result.assets.append(shot)
            url_key = url_map.get(path)
            if url_key:
                result.relations.append(
                    Relation(source_key=shot.key, target_key=url_key, type=RelationType.DEPICTS)
                )

        ctx._cache[_ANALYSIS_KEY] = analyses
        result.notes.append(f"Ingested and analyzed {len(analyses)} screenshot(s).")
        return result


class OCRTextModule(VisionModule):
    name = "ocr_text"
    description = "Extract OCR text, headings, emails, URLs, phones, and secrets."

    async def run(self, ctx: VisionContext) -> ReconResult:
        result = ReconResult(task_id="", module=self.name)
        analyses = ctx._cache.get(_ANALYSIS_KEY, {})
        if not analyses:
            result.notes.append("No analyzed screenshots (run screenshot_ingest first).")
            return result

        for path, analysis in analyses.items():
            shot_key = f"{AssetType.SCREENSHOT.value}:{path.lower()}"
            text = analysis.ocr.text
            if not text:
                continue

            # Full visible/hidden text region for the screenshot.
            region = Asset(
                type=AssetType.TEXT_REGION,
                value=f"text@{_basename(path)}",
                source=self.name,
                attributes={"kind": "page_text", "text": text[:4000], "screenshot": path},
                confidence=round(analysis.ocr.mean_confidence, 3),
            )
            result.assets.append(region)
            result.relations.append(
                Relation(source_key=shot_key, target_key=region.key, type=RelationType.CONTAINS)
            )

            # Headings: the largest text tokens by box area.
            headings = sorted(
                (t for t in analysis.ocr.tokens if t.box and t.text.strip()),
                key=lambda t: t.box.area,
                reverse=True,
            )[:5]
            for i, tok in enumerate(headings):
                h = Asset(
                    type=AssetType.TEXT_REGION,
                    value=f"heading:{tok.text.strip()}@{_basename(path)}#{i}",
                    source=self.name,
                    attributes={"kind": "heading", "text": tok.text.strip(), "screenshot": path},
                    confidence=round(tok.confidence, 3),
                )
                result.assets.append(h)

            # Extracted entities.
            for email in extract_emails(text):
                result.assets.append(
                    Asset(type=AssetType.EMAIL, value=email, source=self.name,
                          attributes={"from": "ocr", "screenshot": path})
                )
            for url in extract_urls(text):
                result.assets.append(
                    Asset(type=AssetType.URL, value=url, source=self.name,
                          attributes={"from": "ocr", "screenshot": path}, confidence=0.6)
                )
            for internal in extract_internal_urls(text):
                result.assets.append(
                    Asset(type=AssetType.ENDPOINT, value=internal, source=self.name,
                          attributes={"from": "ocr", "internal": True, "screenshot": path})
                )
            for phone in extract_phones(text):
                result.assets.append(
                    Asset(type=AssetType.TEXT_REGION, value=f"phone:{phone}", source=self.name,
                          attributes={"kind": "phone", "text": phone, "screenshot": path})
                )
            for kind, value in find_secrets(text):
                result.assets.append(
                    Asset(type=AssetType.SECRET, value=value, source=self.name,
                          attributes={"kind": kind, "from": "ocr", "screenshot": path})
                )

        result.notes.append(f"Extracted text/entities from {len(analyses)} screenshot(s).")
        return result


class ObjectDetectionModule(VisionModule):
    name = "object_detection"
    description = "Turn detected visual elements (buttons, forms, login, …) into assets."

    async def run(self, ctx: VisionContext) -> ReconResult:
        result = ReconResult(task_id="", module=self.name)
        analyses = ctx._cache.get(_ANALYSIS_KEY, {})
        if not analyses:
            result.notes.append("No analyzed screenshots (run screenshot_ingest first).")
            return result

        threshold = ctx.settings.vision.min_confidence
        for path, analysis in analyses.items():
            shot_key = f"{AssetType.SCREENSHOT.value}:{path.lower()}"
            for i, obj in enumerate(analysis.objects):
                if obj.label == "qr_code" or obj.confidence < threshold:
                    continue
                attributes = {
                    "element_type": obj.label,
                    "confidence": obj.confidence,
                    "screenshot": path,
                    **obj.attributes,
                }
                if obj.box is not None:
                    attributes["box"] = obj.box.as_dict()
                element = Asset(
                    type=AssetType.VISUAL_ELEMENT,
                    value=f"{obj.label}@{_basename(path)}#{i}",
                    source=self.name,
                    attributes=attributes,
                    confidence=obj.confidence,
                )
                result.assets.append(element)
                result.relations.append(
                    Relation(source_key=shot_key, target_key=element.key,
                             type=RelationType.CONTAINS)
                )
        result.notes.append(
            f"Detected {len(result.assets)} visual element(s) above "
            f"confidence {threshold}."
        )
        return result


class QRCodeModule(VisionModule):
    name = "qr_codes"
    description = "Surface decoded QR codes detected in screenshots."

    async def run(self, ctx: VisionContext) -> ReconResult:
        result = ReconResult(task_id="", module=self.name)
        analyses = ctx._cache.get(_ANALYSIS_KEY, {})
        for path, analysis in analyses.items():
            shot_key = f"{AssetType.SCREENSHOT.value}:{path.lower()}"
            for obj in analysis.objects:
                if obj.label != "qr_code":
                    continue
                data = obj.attributes.get("data", "")
                qr = Asset(
                    type=AssetType.QR_CODE,
                    value=data or f"qr@{_basename(path)}",
                    source=self.name,
                    attributes={"data": data, "screenshot": path},
                    confidence=obj.confidence,
                )
                result.assets.append(qr)
                result.relations.append(
                    Relation(source_key=shot_key, target_key=qr.key, type=RelationType.CONTAINS)
                )
        result.notes.append(f"Found {len(result.assets)} QR code(s).")
        return result


def build_vision_modules() -> list[VisionModule]:
    """Return the ordered default vision module set.

    Order matters: ``screenshot_ingest`` runs OCR/detection and populates the
    shared ``_cache`` that the later modules read.
    """
    return [
        ScreenshotIngestModule(),
        OCRTextModule(),
        ObjectDetectionModule(),
        QRCodeModule(),
    ]


#: Convenience list of module classes for discovery/registries.
VISION_MODULES = [
    ScreenshotIngestModule,
    OCRTextModule,
    ObjectDetectionModule,
    QRCodeModule,
]
