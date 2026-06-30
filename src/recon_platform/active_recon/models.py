"""Active-recon value objects — the execution record for one tool run.

``ToolExecution`` is the common, normalized record every external tool produces:
the exact command, captured stdout/stderr, exit code, wall-clock duration, and
whether it timed out. It is a Pydantic model so it serializes cleanly into A2A
events, tool output, and episodic memory. Parsed results (assets/relations) are
returned separately as a ``ReconResult`` and merged into the knowledge graph.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class ToolExecution(BaseModel):
    """The outcome of running one external tool once (or after retries)."""

    model_config = ConfigDict(extra="forbid")

    tool: str
    command: list[str] = Field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = None
    duration_seconds: float = 0.0
    timed_out: bool = False
    attempts: int = 1
    #: True when the binary could not be found on PATH (skipped, not failed).
    skipped: bool = False
    skip_reason: str = ""

    @property
    def success(self) -> bool:
        """A clean run: not skipped, not timed out, zero exit code."""
        return not self.skipped and not self.timed_out and self.exit_code == 0

    def summary(self) -> str:
        """A compact one-line status for notes / traces."""
        if self.skipped:
            return f"{self.tool}: skipped ({self.skip_reason})"
        if self.timed_out:
            return f"{self.tool}: timed out after {self.duration_seconds:.1f}s"
        return (
            f"{self.tool}: exit={self.exit_code} "
            f"in {self.duration_seconds:.1f}s ({len(self.stdout)} bytes stdout)"
        )

    def truncated(self, max_bytes: int) -> ToolExecution:
        """Return a copy with stdout/stderr capped to ``max_bytes`` each."""
        if max_bytes <= 0:
            return self
        return self.model_copy(
            update={"stdout": self.stdout[:max_bytes], "stderr": self.stderr[:max_bytes]}
        )
