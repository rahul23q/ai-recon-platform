"""Typed application configuration via pydantic-settings.

All settings are environment-driven (prefix ``RECON_``) with safe offline
defaults so the platform runs without any external service. Nested groups use
``__`` as the delimiter, e.g. ``RECON_LLM__MODEL=claude-opus-4-8``.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class LLMSettings(BaseSettings):
    """LLM reasoning configuration (Anthropic Claude via LangChain)."""

    model_config = SettingsConfigDict(env_prefix="RECON_LLM__")

    enabled: bool = True
    # Default chosen for strong agentic reasoning at reasonable cost. Override
    # with any current Claude model id (e.g. claude-opus-4-8).
    model: str = "claude-sonnet-4-6"
    # Adaptive thinking depth / token spend. Claude 4.6+ uses output_config.effort.
    effort: str = "high"
    max_tokens: int = 8000
    # API key is read from the standard ANTHROPIC_API_KEY env var by the
    # langchain-anthropic client; surfaced here only for presence checks.
    api_key: str | None = Field(default=None, validation_alias="ANTHROPIC_API_KEY")


class HTTPSettings(BaseSettings):
    """Outbound HTTP behaviour for passive recon modules."""

    model_config = SettingsConfigDict(env_prefix="RECON_HTTP__")

    timeout_seconds: float = 15.0
    user_agent: str = "recon-platform/0.1 (authorized-security-testing)"
    max_concurrency: int = 10
    verify_tls: bool = True


class APISettings(BaseSettings):
    """FastAPI / dashboard server settings."""

    model_config = SettingsConfigDict(env_prefix="RECON_API__")

    host: str = "127.0.0.1"
    port: int = 8000


class Settings(BaseSettings):
    """Root settings object — the single source of truth for configuration."""

    model_config = SettingsConfigDict(
        env_prefix="RECON_",
        env_nested_delimiter="__",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    llm: LLMSettings = Field(default_factory=LLMSettings)
    http: HTTPSettings = Field(default_factory=HTTPSettings)
    api: APISettings = Field(default_factory=APISettings)

    # Engagement guardrail: when true, targets must pass the authorization gate.
    authorized_only: bool = True
    # Optional explicit allowlist of authorized targets (domains / hosts).
    # Empty list means "allow any" *unless* you wire a stricter policy in.
    authorized_targets: list[str] = Field(default_factory=list)

    redis_url: str | None = None
    database_url: str | None = None

    log_level: str = "INFO"
    log_json: bool = False

    @property
    def llm_available(self) -> bool:
        """True when LLM reasoning is enabled and an API key is present."""
        return self.llm.enabled and bool(self.llm.api_key)


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings instance (process-wide singleton)."""
    return Settings()
