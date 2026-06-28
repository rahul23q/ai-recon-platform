"""BaseAgent — shared behaviour for every agent.

Encodes the reasoning loop (Thought→Observation→Reason→Plan→Action→Result→
Reflection→Next), publishes structured A2A messages for observability, and
provides an LLM helper that transparently degrades to deterministic behaviour
when no model is configured.

Agents both (a) expose direct async methods the orchestrator calls in dependency
order, and (b) announce their work on the A2A bus so the dashboard/timeline and
other agents can observe it.
"""

from __future__ import annotations

import json
from typing import Any

from recon_platform.core.logging import get_logger
from recon_platform.domain.enums import AgentRole, MessagePriority
from recon_platform.domain.interfaces import LLMProvider, Memory, MessageBus
from recon_platform.domain.schemas import A2AMessage, Evidence, ReasoningTrace


class BaseAgent:
    """Common scaffolding for all agents."""

    role: AgentRole

    def __init__(
        self,
        role: AgentRole,
        bus: MessageBus,
        memory: Memory,
        llm: LLMProvider,
    ) -> None:
        self.role = role
        self.bus = bus
        self.memory = memory
        self.llm = llm
        self.log = get_logger(f"agent.{role.value}")

    async def start(self) -> None:
        """Subscribe to the bus. The event-driven path is available but the
        orchestrator drives the Phase-1 flow via direct calls."""
        await self.bus.subscribe(self.role.value, self.handle)

    async def handle(self, message: A2AMessage) -> None:  # pragma: no cover - extension point
        """Default no-op handler; specialized agents may override."""
        return None

    # -- observability ------------------------------------------------------
    async def announce(
        self,
        *,
        recipient: AgentRole | None,
        reason: str,
        result: dict[str, Any] | None = None,
        evidence: list[Evidence] | None = None,
        confidence: float = 1.0,
        priority: MessagePriority = MessagePriority.NORMAL,
        topic: str = "timeline",
    ) -> None:
        """Publish a structured A2A message describing this agent's action."""
        msg = A2AMessage(
            sender=self.role,
            recipient=recipient,
            topic=topic,
            reason=reason,
            result=result or {},
            evidence=evidence or [],
            confidence=confidence,
            priority=priority,
        )
        await self.bus.publish(msg)

    async def record(self, trace: ReasoningTrace) -> None:
        await self.memory.append_trace(trace)
        self.log.debug("trace", action=trace.action, confidence=trace.confidence)

    # -- reasoning helper ---------------------------------------------------
    async def reason_json(
        self, system: str, prompt: str, schema: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Ask the LLM for a JSON object; return None if unavailable/invalid.

        Callers provide a deterministic fallback when this returns None, so the
        platform never hard-depends on the LLM.
        """
        if not self.llm.available:
            return None
        try:
            raw = await self.llm.complete(system, prompt, json_schema=schema)
            raw = _strip_fences(raw)
            return json.loads(raw)
        except Exception as exc:  # noqa: BLE001
            self.log.warning("llm.reason_failed", error=str(exc))
            return None


def _strip_fences(text: str) -> str:
    """Remove ```json fences a model may add despite instructions."""
    t = text.strip()
    if t.startswith("```"):
        t = t.split("\n", 1)[-1] if "\n" in t else t
        if t.endswith("```"):
            t = t[: -3]
        # drop a leading 'json' language tag line if present
        if t.lstrip().startswith("json"):
            t = t.lstrip()[4:]
    return t.strip()
