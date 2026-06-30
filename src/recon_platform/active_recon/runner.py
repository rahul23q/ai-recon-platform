"""ToolRunner — the shared async subprocess executor.

The single, provider-independent execution engine every external tool runs
through, so timeout / retry / cancellation / output-capture logic lives in **one**
place instead of being reimplemented per tool. It launches a binary with
:func:`asyncio.create_subprocess_exec`, captures stdout/stderr, enforces a
timeout (killing the process group on expiry), retries transient failures, and
propagates cancellation cleanly (killing the child before re-raising).

Resilient by contract: a missing binary or a crash never raises out of
:meth:`ToolRunner.run` — it returns a :class:`~recon_platform.active_recon.models.ToolExecution`
with ``skipped`` / non-zero ``exit_code`` set, so the caller decides what to do.
"""

from __future__ import annotations

import asyncio
import shutil
import time

from recon_platform.active_recon.models import ToolExecution
from recon_platform.core.logging import get_logger

log = get_logger(__name__)


def binary_available(binary: str) -> bool:
    """True when ``binary`` is resolvable on the current ``PATH``.

    A cheap, import-free probe (mirrors ``playwright_available`` / ``desktop_available``)
    so tools degrade to a clean skip when their binary is not installed.
    """
    return shutil.which(binary) is not None


class ToolRunner:
    """Runs external binaries with timeout, retries, and cancellation."""

    def __init__(
        self, *, default_timeout: float = 120.0, max_output_bytes: int = 1_000_000
    ) -> None:
        self._default_timeout = default_timeout
        self._max_output_bytes = max_output_bytes

    async def run(
        self,
        command: list[str],
        *,
        timeout: float | None = None,
        retries: int = 0,
        stdin: str | None = None,
    ) -> ToolExecution:
        """Execute ``command``, retrying up to ``retries`` times on failure.

        Returns the last :class:`ToolExecution`. Never raises for tool failures;
        only :class:`asyncio.CancelledError` propagates (after the child is
        killed), so an aborted run tears the subprocess down cleanly.
        """
        if not command:
            return ToolExecution(tool="", skipped=True, skip_reason="empty command")
        tool = command[0]
        if not binary_available(tool):
            return ToolExecution(
                tool=tool, command=command, skipped=True,
                skip_reason=f"binary '{tool}' not found on PATH",
            )

        timeout = timeout if timeout is not None else self._default_timeout
        attempts = 0
        last: ToolExecution | None = None
        for attempt in range(retries + 1):
            attempts = attempt + 1
            execution = await self._run_once(command, timeout, stdin)
            execution.attempts = attempts
            if execution.success:
                return execution.truncated(self._max_output_bytes)
            last = execution
            if execution.timed_out:
                break  # a timeout won't fix itself by retrying immediately
        assert last is not None
        last.attempts = attempts
        return last.truncated(self._max_output_bytes)

    async def _run_once(
        self, command: list[str], timeout: float, stdin: str | None
    ) -> ToolExecution:
        start = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdin=asyncio.subprocess.PIPE if stdin is not None else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except (FileNotFoundError, OSError) as exc:
            return ToolExecution(
                tool=command[0], command=command, exit_code=127, stderr=str(exc),
                duration_seconds=time.monotonic() - start,
            )

        payload = stdin.encode() if stdin is not None else None
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(payload), timeout)
        except TimeoutError:
            await self._kill(proc)
            return ToolExecution(
                tool=command[0], command=command, timed_out=True,
                stderr=f"timed out after {timeout:.0f}s",
                duration_seconds=time.monotonic() - start,
            )
        except asyncio.CancelledError:
            await self._kill(proc)
            raise
        return ToolExecution(
            tool=command[0],
            command=command,
            stdout=stdout.decode("utf-8", "replace") if stdout else "",
            stderr=stderr.decode("utf-8", "replace") if stderr else "",
            exit_code=proc.returncode,
            duration_seconds=time.monotonic() - start,
        )

    @staticmethod
    async def _kill(proc: asyncio.subprocess.Process) -> None:
        """Best-effort termination of a child process."""
        try:
            proc.kill()
        except ProcessLookupError:
            return
        except Exception as exc:  # noqa: BLE001
            log.warning("tool.kill.failed", error=str(exc))
        try:
            await proc.wait()
        except Exception:  # noqa: BLE001
            pass
