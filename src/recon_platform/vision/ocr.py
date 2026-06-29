"""OCR providers behind a single, provider-independent interface.

``OCRProvider`` is the seam; concrete engines (EasyOCR, RapidOCR, PaddleOCR)
implement it and are imported **lazily** inside ``available`` / ``read`` so the
platform never hard-depends on any of them. ``NullOCRProvider`` is the always-
available fallback (empty result). :func:`build_ocr_provider` selects a provider
by name and transparently falls back to null when the requested engine is absent.

Cloud backends (Google Vision, Azure Vision, AWS Textract) slot in here later by
adding another ``OCRProvider`` subclass — no caller changes required.

All engines run synchronously, so reads are offloaded with ``anyio.to_thread`` to
keep the event loop free (CLAUDE.md rule 6).
"""

from __future__ import annotations

import abc

import anyio

from recon_platform.core.logging import get_logger
from recon_platform.vision.models import BoundingBox, OCRResult, OCRToken

log = get_logger(__name__)


class OCRProvider(abc.ABC):
    """Abstract OCR engine: turn an image path into recognized text tokens."""

    name: str = "ocr"

    def __init__(self, languages: list[str] | None = None) -> None:
        self.languages = languages or ["en"]

    @property
    @abc.abstractmethod
    def available(self) -> bool:
        """True when the underlying engine can be imported and used."""
        raise NotImplementedError

    @abc.abstractmethod
    async def read(self, image_path: str) -> OCRResult:
        """Run OCR over ``image_path`` (never raise; return empty on failure)."""
        raise NotImplementedError


class NullOCRProvider(OCRProvider):
    """Always-available no-op provider returning an empty OCR result."""

    name = "null"

    @property
    def available(self) -> bool:
        return True

    async def read(self, image_path: str) -> OCRResult:
        return OCRResult(provider=self.name)


class EasyOCRProvider(OCRProvider):
    """OCR via the EasyOCR engine (lazy-imported)."""

    name = "easyocr"

    def __init__(self, languages: list[str] | None = None) -> None:
        super().__init__(languages)
        self._reader = None

    @property
    def available(self) -> bool:
        try:
            import easyocr  # noqa: F401
        except Exception:  # noqa: BLE001
            return False
        return True

    def _read_sync(self, image_path: str) -> OCRResult:
        import easyocr

        if self._reader is None:
            self._reader = easyocr.Reader(self.languages, gpu=False, verbose=False)
        tokens: list[OCRToken] = []
        for box, text, conf in self._reader.readtext(image_path):
            xs = [int(p[0]) for p in box]
            ys = [int(p[1]) for p in box]
            bbox = BoundingBox(min(xs), min(ys), max(xs) - min(xs), max(ys) - min(ys))
            tokens.append(OCRToken(text=str(text), confidence=float(conf), box=bbox))
        return OCRResult(provider=self.name, tokens=tokens)

    async def read(self, image_path: str) -> OCRResult:
        try:
            return await anyio.to_thread.run_sync(self._read_sync, image_path)
        except Exception as exc:  # noqa: BLE001
            log.warning("ocr.easyocr.failed", path=image_path, error=str(exc))
            return OCRResult(provider=self.name)


class RapidOCRProvider(OCRProvider):
    """OCR via RapidOCR (ONNX runtime; lazy-imported)."""

    name = "rapidocr"

    def __init__(self, languages: list[str] | None = None) -> None:
        super().__init__(languages)
        self._engine = None

    @property
    def available(self) -> bool:
        try:
            import rapidocr_onnxruntime  # noqa: F401
        except Exception:  # noqa: BLE001
            return False
        return True

    def _read_sync(self, image_path: str) -> OCRResult:
        from rapidocr_onnxruntime import RapidOCR

        if self._engine is None:
            self._engine = RapidOCR()
        out, _ = self._engine(image_path)
        tokens: list[OCRToken] = []
        for entry in out or []:
            box, text, conf = entry[0], entry[1], entry[2]
            xs = [int(p[0]) for p in box]
            ys = [int(p[1]) for p in box]
            bbox = BoundingBox(min(xs), min(ys), max(xs) - min(xs), max(ys) - min(ys))
            tokens.append(OCRToken(text=str(text), confidence=float(conf), box=bbox))
        return OCRResult(provider=self.name, tokens=tokens)

    async def read(self, image_path: str) -> OCRResult:
        try:
            return await anyio.to_thread.run_sync(self._read_sync, image_path)
        except Exception as exc:  # noqa: BLE001
            log.warning("ocr.rapidocr.failed", path=image_path, error=str(exc))
            return OCRResult(provider=self.name)


class PaddleOCRProvider(OCRProvider):
    """OCR via PaddleOCR (lazy-imported)."""

    name = "paddleocr"

    def __init__(self, languages: list[str] | None = None) -> None:
        super().__init__(languages)
        self._engine = None

    @property
    def available(self) -> bool:
        try:
            import paddleocr  # noqa: F401
        except Exception:  # noqa: BLE001
            return False
        return True

    def _read_sync(self, image_path: str) -> OCRResult:
        from paddleocr import PaddleOCR

        if self._engine is None:
            lang = self.languages[0] if self.languages else "en"
            self._engine = PaddleOCR(use_angle_cls=True, lang=lang, show_log=False)
        result = self._engine.ocr(image_path, cls=True)
        tokens: list[OCRToken] = []
        for page in result or []:
            for box, (text, conf) in page or []:
                xs = [int(p[0]) for p in box]
                ys = [int(p[1]) for p in box]
                bbox = BoundingBox(min(xs), min(ys), max(xs) - min(xs), max(ys) - min(ys))
                tokens.append(OCRToken(text=str(text), confidence=float(conf), box=bbox))
        return OCRResult(provider=self.name, tokens=tokens)

    async def read(self, image_path: str) -> OCRResult:
        try:
            return await anyio.to_thread.run_sync(self._read_sync, image_path)
        except Exception as exc:  # noqa: BLE001
            log.warning("ocr.paddleocr.failed", path=image_path, error=str(exc))
            return OCRResult(provider=self.name)


#: Registry of provider classes keyed by their configuration name.
_PROVIDERS: dict[str, type[OCRProvider]] = {
    NullOCRProvider.name: NullOCRProvider,
    EasyOCRProvider.name: EasyOCRProvider,
    RapidOCRProvider.name: RapidOCRProvider,
    PaddleOCRProvider.name: PaddleOCRProvider,
}


def build_ocr_provider(name: str, languages: list[str] | None = None) -> OCRProvider:
    """Return an OCR provider by name, falling back to null when unavailable.

    Selection is forgiving: an unknown name, or a known engine that isn't
    importable in this environment, both resolve to :class:`NullOCRProvider` so a
    run never crashes for lack of an OCR backend.
    """
    cls = _PROVIDERS.get(name.lower())
    if cls is None:
        log.warning("ocr.unknown_provider", requested=name)
        return NullOCRProvider(languages)
    provider = cls(languages)
    if not provider.available:
        log.info("ocr.provider_unavailable", requested=name)
        return NullOCRProvider(languages)
    return provider
