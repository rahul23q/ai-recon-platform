"""Vision value objects + the (future) multimodal-LLM provider interface.

These are framework-agnostic dataclasses exchanged between the OCR providers,
the detector, the vision session, and the modules. They deliberately avoid any
heavy dependency (no numpy / cv2 here) so the contracts are importable anywhere.

``VisionModelProvider`` is an **interface only** — concrete GPT-4V / Claude /
Gemini / Qwen-VL backends are wired in a later phase. Defining it now keeps the
Vision agent provider-independent from day one (Dependency Inversion).
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class BoundingBox:
    """An axis-aligned box in pixel coordinates (origin top-left)."""

    x: int
    y: int
    width: int
    height: int

    def as_dict(self) -> dict[str, int]:
        return {"x": self.x, "y": self.y, "width": self.width, "height": self.height}

    @property
    def area(self) -> int:
        return max(0, self.width) * max(0, self.height)


@dataclass(frozen=True)
class OCRToken:
    """A single recognized text span with its confidence and location."""

    text: str
    confidence: float = 0.0
    box: BoundingBox | None = None


@dataclass
class OCRResult:
    """The full OCR output for one image."""

    provider: str = "null"
    tokens: list[OCRToken] = field(default_factory=list)

    @property
    def text(self) -> str:
        """All recognized text joined with newlines."""
        return "\n".join(t.text for t in self.tokens if t.text)

    @property
    def mean_confidence(self) -> float:
        confs = [t.confidence for t in self.tokens if t.text]
        return sum(confs) / len(confs) if confs else 0.0


@dataclass
class DetectedObject:
    """A detected visual element (button, form, login portal, qr code, …)."""

    label: str
    confidence: float = 0.0
    box: BoundingBox | None = None
    attributes: dict[str, str] = field(default_factory=dict)


@dataclass
class PageClassification:
    """A coarse classification of what a screenshot depicts."""

    page_type: str = "unknown"
    confidence: float = 0.0
    signals: list[str] = field(default_factory=list)


@dataclass
class VisionAnalysis:
    """The combined per-screenshot analysis cached for downstream modules."""

    image_path: str
    ocr: OCRResult
    objects: list[DetectedObject] = field(default_factory=list)
    classification: PageClassification = field(default_factory=PageClassification)
    width: int = 0
    height: int = 0


@runtime_checkable
class VisionModelProvider(Protocol):
    """Interface for a future multimodal-LLM vision backend.

    Concrete providers (Claude Vision, GPT-4.1 Vision, Gemini, Qwen-VL, …) will
    implement this without changing any agent code. Intentionally minimal.
    """

    name: str

    @property
    def available(self) -> bool: ...

    async def describe(self, image_path: str, prompt: str) -> str:
        """Return a natural-language description / answer about the image."""
        ...


class BaseVisionModelProvider(abc.ABC):
    """Convenience ABC for concrete vision-LLM providers (none ship in Phase 3)."""

    name: str = "none"

    @property
    def available(self) -> bool:  # pragma: no cover - no concrete provider yet
        return False

    @abc.abstractmethod
    async def describe(self, image_path: str, prompt: str) -> str:
        raise NotImplementedError
