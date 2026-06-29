"""Mutable run state threaded through the orchestration steps."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from recon_platform.domain.schemas import (
    Asset,
    EngagementContext,
    Finding,
    Plan,
    Relation,
    ReportBundle,
    Verification,
)


class RunState(BaseModel):
    """Accumulates the products of each workflow step for one engagement."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    engagement: EngagementContext
    plan: Plan | None = None
    assets: list[Asset] = Field(default_factory=list)
    relations: list[Relation] = Field(default_factory=list)
    verifications: list[Verification] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    executive_summary: str = ""
    bundle: ReportBundle | None = None
