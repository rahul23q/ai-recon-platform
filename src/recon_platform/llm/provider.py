"""LLM provider implementations.

`AnthropicLLMProvider` wraps `langchain_anthropic.ChatAnthropic` (Claude). When
langchain/anthropic is not installed or no API key is present, callers get
`NullLLMProvider` whose ``available`` is False — agents detect this and fall
back to deterministic behaviour so the platform always runs.

Claude 4.6+ note: we use adaptive thinking + ``output_config.effort`` rather
than the deprecated ``budget_tokens``.
"""

from __future__ import annotations

import json
from typing import Any

import anyio

from recon_platform.core.config import Settings
from recon_platform.core.logging import get_logger

log = get_logger(__name__)


class NullLLMProvider:
    """No-op provider used when no LLM is configured."""

    available = False

    async def complete(
        self, system: str, prompt: str, *, json_schema: dict[str, Any] | None = None
    ) -> str:
        raise RuntimeError("LLM is not available (NullLLMProvider).")


class AnthropicLLMProvider:
    """Claude-backed provider using LangChain's ChatAnthropic."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._client = None  # lazy
        self._available = False
        self._init_client()

    @property
    def available(self) -> bool:
        return self._available

    def _init_client(self) -> None:
        if not self._settings.llm_available:
            log.info("llm.disabled", reason="no api key or disabled")
            return
        try:
            from langchain_anthropic import ChatAnthropic
        except ImportError:  # pragma: no cover - optional dep
            log.warning("llm.langchain_missing", hint="pip install '.[llm]'")
            return

        # Claude 4.6+: adaptive thinking; effort controls depth via output_config.
        self._client = ChatAnthropic(
            model=self._settings.llm.model,
            max_tokens=self._settings.llm.max_tokens,
            thinking={"type": "adaptive"},
            model_kwargs={"output_config": {"effort": self._settings.llm.effort}},
        )
        self._available = True
        log.info("llm.ready", model=self._settings.llm.model)

    async def complete(
        self, system: str, prompt: str, *, json_schema: dict[str, Any] | None = None
    ) -> str:
        if not self._available or self._client is None:
            raise RuntimeError("LLM is not available.")

        if json_schema is not None:
            prompt = (
                f"{prompt}\n\nRespond with ONLY valid JSON matching this schema "
                f"(no prose, no markdown fences):\n{json.dumps(json_schema)}"
            )

        messages = [("system", system), ("human", prompt)]

        # ChatAnthropic.invoke is synchronous; run it off the event loop.
        def _invoke() -> str:
            response = self._client.invoke(messages)  # type: ignore[union-attr]
            content = response.content
            if isinstance(content, list):  # blocks -> concat text blocks
                return "".join(
                    b.get("text", "") if isinstance(b, dict) else str(b) for b in content
                )
            return str(content)

        text = await anyio.to_thread.run_sync(_invoke)
        return text.strip()


def build_llm_provider(settings: Settings):
    """Factory: return a working Claude provider or the null fallback."""
    provider = AnthropicLLMProvider(settings)
    if provider.available:
        return provider
    return NullLLMProvider()
