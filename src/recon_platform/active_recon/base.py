"""The ExternalTool framework + the context handed to every tool.

An ``ExternalTool`` is the uniform wrapper around one security binary. It is the
active-recon counterpart to :class:`~recon_platform.recon.base.ReconModule`, but
instead of doing I/O itself it (1) declares its binary, (2) builds a command
line, and (3) parses the captured stdout into the platform's common domain models
(``Asset`` / ``Relation``). Execution — timeout, retries, cancellation, output
capture — is delegated to the shared
:class:`~recon_platform.active_recon.runner.ToolRunner`, so every tool behaves
consistently and stays testable with mocked output (no real binary required).

Resilience is part of the contract: ``available()`` gates on the binary being on
``PATH``; a missing binary, a non-zero exit, or a parse error is captured in the
returned ``ReconResult.errors`` / notes rather than raised, so one tool never
aborts the run.
"""

from __future__ import annotations

import abc

from recon_platform.active_recon.models import ToolExecution
from recon_platform.active_recon.runner import ToolRunner, binary_available
from recon_platform.core.config import Settings
from recon_platform.domain.enums import ToolPermission
from recon_platform.domain.schemas import ReconResult


class ActiveToolContext:
    """Shared resources handed to every external tool during a run.

    ``runner`` is the shared async subprocess executor; ``settings`` carries the
    per-tool execution controls (timeout, retries, wordlist, …). The normalized
    ``target`` host is what the command lines are built against.
    """

    def __init__(self, target: str, runner: ToolRunner, settings: Settings) -> None:
        self.target = target
        self.runner = runner
        self.settings = settings


class ExternalTool(abc.ABC):
    """Abstract base for an external security tool wrapped as a plugin."""

    #: Stable identifier used in results, events, and reports.
    name: str = "tool"
    #: Human description.
    description: str = ""
    #: The binary discovered on PATH (often equal to ``name``).
    binary: str = "tool"
    #: Active tools touch the network intrusively and shell out to a subprocess.
    permissions: tuple[ToolPermission, ...] = (
        ToolPermission.NETWORK_ACTIVE,
        ToolPermission.SUBPROCESS,
    )

    def available(self) -> bool:
        """True when this tool's binary is installed on ``PATH``."""
        return binary_available(self.binary)

    @abc.abstractmethod
    def build_command(self, target: str, settings: Settings) -> list[str]:
        """Return the argv to execute, or ``[]`` to skip (e.g. missing config)."""
        raise NotImplementedError

    @abc.abstractmethod
    def parse(self, execution: ToolExecution, target: str) -> ReconResult:
        """Normalize the tool's stdout into a ``ReconResult`` (never raise)."""
        raise NotImplementedError

    async def run(self, ctx: ActiveToolContext) -> tuple[ReconResult, ToolExecution]:
        """Run the tool end-to-end and return ``(parsed_result, execution)``.

        Skips cleanly (no subprocess) when the binary is missing or the command
        builder declines; captures any parse failure into ``result.errors``.
        """
        if not self.available():
            result = self._empty()
            result.notes.append(f"'{self.binary}' not installed; skipped.")
            return result, ToolExecution(
                tool=self.name, skipped=True, skip_reason=f"'{self.binary}' not on PATH"
            )

        command = self.build_command(ctx.target, ctx.settings)
        if not command:
            result = self._empty()
            result.notes.append(f"{self.name}: no command built (missing config); skipped.")
            return result, ToolExecution(
                tool=self.name, skipped=True, skip_reason="no command (missing config)"
            )

        execution = await ctx.runner.run(
            command,
            timeout=ctx.settings.active_recon.timeout_seconds,
            retries=ctx.settings.active_recon.retries,
        )
        execution.tool = self.name

        if execution.skipped:
            result = self._empty()
            result.notes.append(execution.summary())
            return result, execution

        try:
            result = self.parse(execution, ctx.target)
        except Exception as exc:  # noqa: BLE001
            result = self._empty()
            result.errors.append(f"{self.name} parse failed: {exc}")
        if execution.timed_out:
            result.errors.append(execution.summary())
        else:
            result.notes.append(execution.summary())
        return result, execution

    def _empty(self) -> ReconResult:
        return ReconResult(task_id="", module=self.name)
