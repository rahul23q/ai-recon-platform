"""Protocol interfaces — the seams that make every component replaceable.

Infrastructure implements these; agents and orchestration depend only on them.
This is the heart of the Dependency Inversion Principle in the platform.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any, Protocol, runtime_checkable

from recon_platform.domain.enums import (
    AgentRole,
    AssetType,
    MemoryScope,
    ToolPermission,
)
from recon_platform.domain.schemas import (
    A2AMessage,
    Asset,
    EngagementContext,
    Plan,
    ReasoningTrace,
    Relation,
)

# A subscriber callback receives a message and handles it asynchronously.
MessageHandler = Callable[[A2AMessage], Awaitable[None]]


@runtime_checkable
class MessageBus(Protocol):
    """Async pub/sub bus for A2A messages."""

    async def publish(self, message: A2AMessage) -> None: ...

    async def subscribe(self, topic: str, handler: MessageHandler) -> None: ...

    async def request(self, message: A2AMessage, timeout: float = 60.0) -> A2AMessage:
        """Send a message and await a correlated response."""
        ...

    def history(self) -> list[A2AMessage]:
        """Return all messages seen so far (for the dashboard/timeline)."""
        ...


@runtime_checkable
class LLMProvider(Protocol):
    """Abstraction over the reasoning LLM (Claude by default)."""

    @property
    def available(self) -> bool: ...

    async def complete(
        self,
        system: str,
        prompt: str,
        *,
        json_schema: dict[str, Any] | None = None,
    ) -> str:
        """Return the model's text (or JSON string when json_schema is given)."""
        ...


@runtime_checkable
class Memory(Protocol):
    """Layered memory store (short-term / working / long-term / episodic)."""

    async def remember(self, scope: MemoryScope, key: str, value: Any) -> None: ...

    async def recall(self, scope: MemoryScope, key: str) -> Any | None: ...

    async def search(self, scope: MemoryScope, query: str) -> list[Any]: ...

    async def append_trace(self, trace: ReasoningTrace) -> None: ...

    def traces(self) -> list[ReasoningTrace]: ...


@runtime_checkable
class KnowledgeGraph(Protocol):
    """Relationship graph over discovered assets."""

    def add_asset(self, asset: Asset) -> None: ...

    def add_relation(self, relation: Relation) -> None: ...

    def assets(self, type_: AssetType | None = None) -> list[Asset]: ...

    def relations(self) -> list[Relation]: ...

    def neighbors(self, asset_key: str) -> list[Asset]: ...

    def to_dict(self) -> dict[str, Any]: ...


@runtime_checkable
class Tool(Protocol):
    """A uniform callable capability (the MCP-style tool contract)."""

    name: str
    description: str
    permissions: list[ToolPermission]
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]

    async def run(self, **kwargs: Any) -> dict[str, Any]: ...


@runtime_checkable
class ToolRegistry(Protocol):
    """Registry that exposes tools by name (MCP server surface)."""

    def register(self, tool: Tool) -> None: ...

    def get(self, name: str) -> Tool: ...

    def list(self) -> list[Tool]: ...


@runtime_checkable
class Plugin(Protocol):
    """A packaged capability with metadata; produces one or more Tools."""

    name: str
    version: str
    description: str

    def tools(self) -> list[Tool]: ...


@runtime_checkable
class Agent(Protocol):
    """An autonomous agent participating in the A2A conversation."""

    role: AgentRole

    async def start(self) -> None:
        """Subscribe to the bus / initialize resources."""
        ...

    async def handle(self, message: A2AMessage) -> None:
        """React to an inbound message."""
        ...


@runtime_checkable
class ReportRenderer(Protocol):
    """Renders a ReportBundle into a concrete format (md/html/json/…)."""

    format: str

    def render(self, bundle: Any) -> str: ...


@runtime_checkable
class Orchestrator(Protocol):
    """Drives an engagement through its workflow, returning a ReportBundle."""

    async def run(self, engagement: EngagementContext) -> Any: ...

    def stream_events(self) -> AsyncIterator[dict[str, Any]]:
        """Yield live events for the dashboard."""
        ...


@runtime_checkable
class Planner(Protocol):
    """Produces a Plan for an engagement (LLM-backed or deterministic)."""

    async def make_plan(self, engagement: EngagementContext) -> Plan: ...
