"""Core domain entities and value objects (Pydantic models).

These are the structured contracts exchanged between agents and persisted to
memory. They are framework-agnostic and safe to import anywhere.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from recon_platform.domain.enums import (
    AgentRole,
    AssetType,
    MessagePriority,
    RelationType,
    Severity,
    TaskStatus,
    VerificationStatus,
    WorkflowType,
)


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=False)


# ---------------------------------------------------------------------------
# Engagement
# ---------------------------------------------------------------------------
class EngagementContext(_Base):
    """The authorized scope and metadata for a recon run."""

    id: str = Field(default_factory=lambda: _new_id("eng"))
    target: str
    workflow: WorkflowType = WorkflowType.PASSIVE_RECON
    authorized: bool = False
    notes: str | None = None
    created_at: datetime = Field(default_factory=_utcnow)


# ---------------------------------------------------------------------------
# Tasks (Planner output)
# ---------------------------------------------------------------------------
class Task(_Base):
    """A unit of work the Planner assigns to an agent."""

    id: str = Field(default_factory=lambda: _new_id("task"))
    title: str
    description: str = ""
    assigned_role: AgentRole
    status: TaskStatus = TaskStatus.PENDING
    priority: MessagePriority = MessagePriority.NORMAL
    # IDs of tasks that must complete before this one may start.
    depends_on: list[str] = Field(default_factory=list)
    # Free-form parameters for the assigned agent (e.g. which recon modules).
    params: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=_utcnow)


class Plan(_Base):
    """An ordered set of tasks produced by the Planner agent."""

    id: str = Field(default_factory=lambda: _new_id("plan"))
    engagement_id: str
    objective: str
    tasks: list[Task] = Field(default_factory=list)
    rationale: str = ""
    created_at: datetime = Field(default_factory=_utcnow)


# ---------------------------------------------------------------------------
# Assets, relations, findings (Recon / Analysis output)
# ---------------------------------------------------------------------------
class Asset(_Base):
    """A discovered entity (domain, IP, endpoint, technology, …)."""

    id: str = Field(default_factory=lambda: _new_id("asset"))
    type: AssetType
    value: str
    source: str = "unknown"  # which module/tool surfaced it
    attributes: dict[str, Any] = Field(default_factory=dict)
    confidence: float = 1.0
    discovered_at: datetime = Field(default_factory=_utcnow)

    @property
    def key(self) -> str:
        """Stable identity for dedup across modules."""
        return f"{self.type.value}:{self.value.lower()}"


class Relation(_Base):
    """A directed edge between two assets in the knowledge graph."""

    source_key: str
    target_key: str
    type: RelationType
    attributes: dict[str, Any] = Field(default_factory=dict)


class Evidence(_Base):
    """A piece of supporting evidence attached to a finding or message."""

    label: str
    detail: str
    data: dict[str, Any] = Field(default_factory=dict)


class Verification(_Base):
    """A cross-source verdict about a single claim (e.g. one security header).

    Produced by the Verification stage before analysis. ``sources`` lists the
    independent observers that contributed (e.g. ``passive-http``, ``browser``,
    ``chrome-devtools``); ``status`` records whether they agreed.
    """

    subject: str  # stable key, e.g. "security-header:content-security-policy"
    claim: str  # the asserted state, e.g. "present" | "missing"
    status: VerificationStatus = VerificationStatus.NEEDS_VERIFICATION
    confidence: float = 0.5
    sources: list[str] = Field(default_factory=list)
    detail: str = ""
    created_at: datetime = Field(default_factory=_utcnow)


class Finding(_Base):
    """An analyzed observation worth reporting, with severity + evidence."""

    id: str = Field(default_factory=lambda: _new_id("find"))
    title: str
    description: str = ""
    severity: Severity = Severity.INFO
    category: str = "recon"
    asset_keys: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    recommendation: str = ""
    # Mapping hooks for later enrichment (OWASP / CWE / MITRE / CVSS).
    references: dict[str, Any] = Field(default_factory=dict)
    confidence: float = 0.8
    # Cross-source verification metadata (Phase 3.1). Defaults to a single-source
    # "likely" verdict so every finding carries a status without forcing callers
    # to set one; cross-verified findings upgrade/downgrade it explicitly.
    verification_status: VerificationStatus = VerificationStatus.LIKELY
    verification_sources: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_utcnow)


class ReconResult(_Base):
    """Aggregated output of a recon task (assets + relations + raw notes)."""

    task_id: str
    module: str
    assets: list[Asset] = Field(default_factory=list)
    relations: list[Relation] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# LLM reasoning trace
# ---------------------------------------------------------------------------
class ReasoningTrace(_Base):
    """The structured reasoning every agent action records.

    Mirrors the Thought→Observation→Plan→Action→Result→Reflection loop.
    """

    agent: AgentRole
    thought: str = ""
    observation: str = ""
    reason: str = ""
    plan: str = ""
    action: str = ""
    tool: str | None = None
    result: str = ""
    reflection: str = ""
    next_action: str = ""
    confidence: float = 0.5
    recovery_plan: str = ""
    created_at: datetime = Field(default_factory=_utcnow)


# ---------------------------------------------------------------------------
# A2A message envelope
# ---------------------------------------------------------------------------
class A2AMessage(_Base):
    """Structured Agent-to-Agent message envelope.

    Carries everything the spec requires: task, priority, reason, evidence,
    dependencies, result, and confidence — plus routing metadata.
    """

    id: str = Field(default_factory=lambda: _new_id("msg"))
    correlation_id: str | None = None  # ties a request/response pair together
    sender: AgentRole
    recipient: AgentRole | None = None  # None => broadcast on topic
    topic: str = "default"

    task: Task | None = None
    priority: MessagePriority = MessagePriority.NORMAL
    reason: str = ""
    dependencies: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    # Arbitrary structured payload (e.g. ReconResult / Finding lists serialized).
    result: dict[str, Any] = Field(default_factory=dict)
    confidence: float = 1.0
    created_at: datetime = Field(default_factory=_utcnow)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
class ReportBundle(_Base):
    """Everything needed to render a report for an engagement."""

    engagement: EngagementContext
    plan: Plan | None = None
    assets: list[Asset] = Field(default_factory=list)
    relations: list[Relation] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    traces: list[ReasoningTrace] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=_utcnow)

    @property
    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            counts[sev] = counts.get(sev, 0) + 1
        return counts
