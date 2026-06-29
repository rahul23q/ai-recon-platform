"""Vision-agent infrastructure (Phase 3).

An OCR + visual-intelligence layer that mirrors the ``recon/`` and ``browser/``
packages: ``VisionModule``s read the screenshots produced by the Browser agent,
run provider-independent OCR and object detection over them, and return assets /
relations, driven by :class:`~recon_platform.agents.vision.VisionAgent`.

Everything here is **opt-in and off by default** (``settings.vision.enabled``)
and degrades gracefully when no vision backend is installed — OCR engines, image
libraries, and the (future) multimodal LLM are all imported lazily inside their
providers, so importing this package never requires the optional ``vision`` extra.

Design seams (provider-independent, swappable):

* :mod:`recon_platform.vision.ocr` — the ``OCRProvider`` interface + EasyOCR /
  RapidOCR / PaddleOCR / null implementations.
* :mod:`recon_platform.vision.detector` — the ``ObjectDetector`` interface + a
  dependency-free heuristic detector and page classifier.
* :mod:`recon_platform.vision.models` — pure data structures + the
  ``VisionModelProvider`` interface for future GPT-4V / Claude / Gemini vision.
"""
