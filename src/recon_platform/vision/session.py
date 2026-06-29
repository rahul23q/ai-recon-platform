"""VisionSession — the OCR + detection lifecycle wrapper.

The Phase-3 counterpart to :class:`~recon_platform.browser.session.BrowserSession`.
It owns the configured OCR provider and object detector, analyzes a screenshot
(OCR → detection → page classification → optional QR scan), and can draw labelled
bounding boxes for report evidence. The heavy stack (image libraries, OCR engines,
OpenCV) is imported **lazily** and only when present; callers gate on
:func:`vision_available` and skip cleanly otherwise — the same degradation pattern
the Browser / LangGraph layers use.
"""

from __future__ import annotations

from types import TracebackType

from recon_platform.core.config import Settings
from recon_platform.core.logging import get_logger
from recon_platform.vision.detector import build_detector, classify_page
from recon_platform.vision.models import BoundingBox, DetectedObject, VisionAnalysis
from recon_platform.vision.ocr import build_ocr_provider

log = get_logger(__name__)

# Modules that, if any is importable, make real visual analysis possible.
_VISION_BACKENDS = ("easyocr", "rapidocr_onnxruntime", "paddleocr", "cv2", "PIL", "numpy")


def vision_available() -> bool:
    """True when at least one image/OCR backend can be imported.

    Mirrors ``playwright_available`` — a cheap lazy probe so the vision step
    degrades to a no-op when the optional ``vision`` extra is not installed.
    """
    for mod in _VISION_BACKENDS:
        try:
            __import__(mod)
            return True
        except Exception:  # noqa: BLE001
            continue
    return False


class VisionSession:
    """Owns the OCR provider + detector and analyzes screenshots.

    Usage::

        async with VisionSession(settings) as session:
            analysis = await session.analyze(path)

    Resilient throughout: a failure analyzing one image yields an empty
    :class:`~recon_platform.vision.models.VisionAnalysis`, never an exception.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        vs = settings.vision
        self.ocr = build_ocr_provider(vs.ocr_provider, list(vs.languages))
        self.detector = build_detector(vs.detector)

    # -- lifecycle (symmetry with BrowserSession) ---------------------------
    async def __aenter__(self) -> VisionSession:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        return None

    # -- analysis -----------------------------------------------------------
    async def analyze(self, image_path: str) -> VisionAnalysis:
        """Run OCR + detection + classification (+ QR scan) over one screenshot."""
        ocr = await self.ocr.read(image_path)
        objects: list[DetectedObject] = []
        try:
            objects = await self.detector.detect(image_path, ocr)
        except Exception as exc:  # noqa: BLE001
            log.warning("vision.detect.failed", path=image_path, error=str(exc))
        objects += self._detect_qr_codes(image_path)
        classification = classify_page(ocr.text)
        width, height = self._image_size(image_path)
        return VisionAnalysis(
            image_path=image_path,
            ocr=ocr,
            objects=objects,
            classification=classification,
            width=width,
            height=height,
        )

    def _image_size(self, image_path: str) -> tuple[int, int]:
        try:
            from PIL import Image

            with Image.open(image_path) as img:
                return int(img.width), int(img.height)
        except Exception:  # noqa: BLE001
            return 0, 0

    def _detect_qr_codes(self, image_path: str) -> list[DetectedObject]:
        """Detect QR codes via OpenCV when available (best-effort)."""
        try:
            import cv2  # noqa: F401

            image = cv2.imread(image_path)
            if image is None:
                return []
            detector = cv2.QRCodeDetector()
            data, points, _ = detector.detectAndDecode(image)
            if not data:
                return []
            box = None
            if points is not None and len(points):
                pts = points.reshape(-1, 2)
                xs = [int(p[0]) for p in pts]
                ys = [int(p[1]) for p in pts]
                box = BoundingBox(min(xs), min(ys), max(xs) - min(xs), max(ys) - min(ys))
            return [DetectedObject(label="qr_code", confidence=0.9, box=box,
                                   attributes={"data": str(data)})]
        except Exception:  # noqa: BLE001
            return []

    async def annotate(
        self, image_path: str, objects: list[DetectedObject], out_path: str
    ) -> str | None:
        """Draw labelled boxes over ``image_path`` → ``out_path`` (best-effort)."""
        boxed = [o for o in objects if o.box is not None]
        if not boxed:
            return None
        try:
            from PIL import Image, ImageDraw

            with Image.open(image_path).convert("RGB") as img:
                draw = ImageDraw.Draw(img)
                for obj in boxed:
                    b = obj.box
                    assert b is not None
                    draw.rectangle(
                        [(b.x, b.y), (b.x + b.width, b.y + b.height)],
                        outline=(220, 30, 30),
                        width=3,
                    )
                    draw.text((b.x + 2, max(0, b.y - 12)), obj.label, fill=(220, 30, 30))
                img.save(out_path)
            return out_path
        except Exception as exc:  # noqa: BLE001
            log.warning("vision.annotate.failed", path=image_path, error=str(exc))
            return None
