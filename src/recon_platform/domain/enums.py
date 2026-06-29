"""Enumerations shared across the domain."""

from __future__ import annotations

from enum import Enum


class StrEnum(str, Enum):
    """String-valued enum (stable JSON serialization, py3.11-compatible)."""

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return self.value


class AgentRole(StrEnum):
    PLANNER = "planner"
    RECON = "recon"
    ANALYSIS = "analysis"
    REPORTING = "reporting"
    MEMORY = "memory"
    KNOWLEDGE_GRAPH = "knowledge_graph"
    BROWSER = "browser"
    VISION = "vision"
    VERIFICATION = "verification"
    NETWORK = "network"
    API = "api"
    HUMAN = "human"


class MessagePriority(StrEnum):
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


class TaskStatus(StrEnum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    BLOCKED = "blocked"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class VerificationStatus(StrEnum):
    """Cross-source confidence in a finding (Phase 3.1 verification pipeline).

    * ``VERIFIED`` — corroborated by ≥2 independent sources that agree.
    * ``LIKELY`` — single-source, deterministic, but not cross-verified.
    * ``NEEDS_VERIFICATION`` — sources disagree (or none could confirm).
    * ``FALSE_POSITIVE`` — a claim contradicted by a more authoritative source
      (e.g. a header reported "missing" by passive HTTP but observed in-browser).
    """

    VERIFIED = "verified"
    LIKELY = "likely"
    NEEDS_VERIFICATION = "needs_verification"
    FALSE_POSITIVE = "false_positive"

    @property
    def rank(self) -> int:
        return {
            "verified": 3,
            "likely": 2,
            "needs_verification": 1,
            "false_positive": 0,
        }[self.value]


class AssetType(StrEnum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    URL = "url"
    ENDPOINT = "endpoint"
    CERTIFICATE = "certificate"
    JS_FILE = "js_file"
    EMAIL = "email"
    TECHNOLOGY = "technology"
    COOKIE = "cookie"
    TOKEN = "token"
    SECRET = "secret"
    HEADER = "header"
    PORT = "port"
    # Visual assets (Phase 3 — Vision agent). VISUAL_ELEMENT carries its concrete
    # kind (button/form/login/…) in ``attributes["element_type"]`` so the enum
    # stays small while remaining expressive, mirroring the HEADER convention.
    SCREENSHOT = "screenshot"
    VISUAL_ELEMENT = "visual_element"
    TEXT_REGION = "text_region"
    QR_CODE = "qr_code"


class RelationType(StrEnum):
    RESOLVES_TO = "resolves_to"
    SUBDOMAIN_OF = "subdomain_of"
    HOSTS = "hosts"
    SERVES = "serves"
    REFERENCES = "references"
    USES = "uses"
    EXPOSES = "exposes"
    ISSUED_FOR = "issued_for"
    CONTAINS = "contains"
    DEPICTS = "depicts"  # a screenshot depicts a page / URL


class WorkflowType(StrEnum):
    PASSIVE_RECON = "passive_recon"
    ACTIVE_RECON = "active_recon"
    API_DISCOVERY = "api_discovery"
    JS_ANALYSIS = "js_analysis"
    AUTH = "authentication"
    REPORT = "report"


class MemoryScope(StrEnum):
    SHORT_TERM = "short_term"
    WORKING = "working"
    LONG_TERM = "long_term"
    EPISODIC = "episodic"


class ToolPermission(StrEnum):
    """Capability flags a plugin/tool declares; used for authorization gating."""

    NETWORK_PASSIVE = "network:passive"
    NETWORK_ACTIVE = "network:active"
    FILESYSTEM_READ = "filesystem:read"
    FILESYSTEM_WRITE = "filesystem:write"
    BROWSER = "browser"
    SUBPROCESS = "subprocess"
