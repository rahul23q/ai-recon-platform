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


class BrowserSettings(BaseSettings):
    """Browser-agent configuration (Playwright + Chrome DevTools).

    Off by default so the foundation stays offline-capable and CI without
    Playwright installed is unaffected. Enable with ``RECON_BROWSER__ENABLED=1``
    (or the ``--browser`` CLI flag) after ``pip install '.[browser]' &&
    playwright install chromium``.
    """

    model_config = SettingsConfigDict(env_prefix="RECON_BROWSER__")

    enabled: bool = False
    headless: bool = True
    engine: str = "chromium"
    nav_timeout_seconds: float = 30.0
    screenshot: bool = True
    screenshot_dir: str = "reports/screenshots"
    # Navigation budget (the foundation visits the home page only).
    max_pages: int = 1


class VisionSettings(BaseSettings):
    """Vision-agent configuration (OCR + visual intelligence over screenshots).

    Off by default and provider-independent: the OCR backend and the (future)
    vision-LLM backend are selected by name and resolved lazily, so the platform
    installs and runs without the heavy ``vision`` extra. When disabled or when
    no vision backend is importable, the vision step degrades to a clean no-op.
    """

    model_config = SettingsConfigDict(env_prefix="RECON_VISION__")

    enabled: bool = False
    # OCR provider: easyocr | rapidocr | paddleocr | null. Unknown / unavailable
    # providers fall back to the null provider (empty OCR) so runs never crash.
    ocr_provider: str = "easyocr"
    languages: list[str] = Field(default_factory=lambda: ["en"])
    # Object detector: heuristic (OCR-text driven, dependency-free) | null.
    detector: str = "heuristic"
    # Future multimodal LLM backend: none | claude | openai | gemini | … (the
    # interface exists now; concrete providers arrive in a later phase).
    model_provider: str = "none"
    # Analysis budget + thresholds.
    max_screenshots: int = 20
    min_confidence: float = 0.4
    # Annotated screenshots (bounding boxes) — best-effort, requires Pillow.
    annotate: bool = True
    annotate_dir: str = "reports/vision"


class DesktopSettings(BaseSettings):
    """Desktop-agent configuration (mouse / keyboard / windows / clipboard).

    **Off by default** and behind a *two-key* safety posture so the platform
    stays passive: ``enabled`` turns the agent on for read-only observation
    (window discovery, screen capture, clipboard read); synthetic input (mouse
    movement/clicks, keystrokes, file-dialog automation) additionally requires
    ``allow_input=True``. When disabled or when no desktop backend is importable,
    the desktop step degrades to a clean no-op.

    The input backend is provider-independent and resolved by name: ``pyautogui``
    drives real input (lazy-imported, requires the ``desktop`` extra), ``null``
    records intended actions without performing them. An unknown / uninstalled
    backend falls back to ``null`` so a run never crashes.
    """

    model_config = SettingsConfigDict(env_prefix="RECON_DESKTOP__")

    enabled: bool = False
    # Second safety gate: even when enabled, real mouse/keyboard input only fires
    # when this is true. Off ⇒ interactions are recorded as planned (dry-run).
    allow_input: bool = False
    # Input backend: pyautogui | null. Unknown/unavailable falls back to null.
    backend: str = "pyautogui"
    # Screen-capture evidence of the desktop (best-effort; mss / Pillow).
    screenshot: bool = True
    screenshot_dir: str = "reports/desktop"
    # Observation / interaction budgets.
    max_windows: int = 50
    max_actions: int = 25
    # Cursor move duration (seconds) for synthetic mouse movement.
    move_duration: float = 0.0
    # Minimum confidence a Vision-detected element needs before the agent will
    # plan a click on it (reuses the Vision element confidences).
    min_element_confidence: float = 0.5


class ActiveReconSettings(BaseSettings):
    """Active-recon configuration (external tool plugins — Phase 5).

    **Off by default** and behind a *two-key* safety posture, because active
    scanning is intrusive: ``enabled`` turns the agent on, and ``authorized`` is a
    separate explicit acknowledgment that the operator is permitted to actively
    scan the target. Active tools run only when **both** are true *and* the target
    passes the authorization gate.

    Tools are external binaries discovered on ``PATH`` and invoked via subprocess;
    none are imported. A missing binary is skipped gracefully (never a crash), so
    the platform installs and runs without any of them present.
    """

    model_config = SettingsConfigDict(env_prefix="RECON_ACTIVE_RECON__")

    enabled: bool = False
    # Second safety gate: explicit authorization to run intrusive/active scans.
    authorized: bool = False
    # Optional subset of tool names to run (empty ⇒ all available default tools).
    tools: list[str] = Field(default_factory=list)
    # Per-tool execution controls.
    timeout_seconds: float = 120.0
    retries: int = 0
    # Cap stored stdout/stderr so a chatty tool can't blow up memory / reports.
    max_output_bytes: int = 1_000_000
    # Wordlist path for content-discovery tools (ffuf / dirsearch). When empty,
    # those tools are skipped with a clear note rather than guessing a list.
    wordlist: str = ""
    # Optional nuclei severity filter (e.g. "low,medium,high,critical").
    nuclei_severity: str = ""
    # Optional shared rate limit (requests/sec) for tools that accept one.
    rate_limit: int = 0


class NetworkSettings(BaseSettings):
    """Network-agent configuration (Phase 6 — request/response analysis).

    **Off by default.** The Network agent is a passive correlation layer: it reads
    the HTTP headers, cookies, tokens, endpoints, and captured traffic already in
    the knowledge graph (from passive recon, the Browser agent, and active recon)
    and analyzes them — JWT inspection, header/CORS hygiene, GraphQL/REST traffic
    classification, and WebSocket review — without issuing any new requests. It
    therefore has no external dependency and degrades to a clean no-op when
    disabled.
    """

    model_config = SettingsConfigDict(env_prefix="RECON_NETWORK__")

    enabled: bool = False
    # Decode JWTs found in headers / tokens / URLs (header+payload only; the
    # signature is never verified — this is inspection, not validation).
    decode_jwt: bool = True
    # Flag insecure (unencrypted ``ws://``) WebSocket endpoints.
    flag_insecure_websocket: bool = True
    # Classify endpoints as GraphQL / REST traffic.
    classify_apis: bool = True
    # Analysis budget: cap how many items each module processes.
    max_items: int = 500


class APIDiscoverySettings(BaseSettings):
    """API-discovery agent configuration (Phase 7 — API characterization).

    **Off by default.** The API Discovery agent is a passive correlation layer:
    it reads the endpoints, headers, JS files, and the Network agent's classified
    API traffic already in the knowledge graph and characterizes the APIs behind
    them — REST resource/version inference, GraphQL / SOAP / gRPC detection,
    request-parameter extraction, and authentication-scheme detection — without
    issuing any new requests. It has no external dependency and degrades to a
    clean no-op when disabled.
    """

    model_config = SettingsConfigDict(env_prefix="RECON_API_DISCOVERY__")

    enabled: bool = False
    # Infer REST APIs (base path / version / resources) from endpoint URLs.
    infer_rest: bool = True
    # Discover GraphQL / SOAP / gRPC APIs from endpoints and captured traffic.
    discover_graphql: bool = True
    discover_soap_grpc: bool = True
    # Detect authentication schemes from request/response headers.
    detect_auth: bool = True
    # Analysis budget: cap how many items each module processes.
    max_items: int = 500


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
    browser: BrowserSettings = Field(default_factory=BrowserSettings)
    vision: VisionSettings = Field(default_factory=VisionSettings)
    desktop: DesktopSettings = Field(default_factory=DesktopSettings)
    active_recon: ActiveReconSettings = Field(default_factory=ActiveReconSettings)
    network: NetworkSettings = Field(default_factory=NetworkSettings)
    api_discovery: APIDiscoverySettings = Field(default_factory=APIDiscoverySettings)

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
