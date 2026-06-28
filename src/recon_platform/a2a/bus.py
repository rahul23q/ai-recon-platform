"""In-memory async A2A message bus.

Implements the `MessageBus` Protocol with topic-based pub/sub, a request/response
pattern using correlation IDs + futures, and a full message history that powers
the dashboard timeline. A Redis-backed bus can be dropped in later behind the
same Protocol without touching agents.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict

from recon_platform.core.logging import get_logger
from recon_platform.domain.interfaces import MessageHandler
from recon_platform.domain.schemas import A2AMessage

log = get_logger(__name__)


class InMemoryMessageBus:
    """Single-process async pub/sub bus."""

    def __init__(self) -> None:
        self._subscribers: dict[str, list[MessageHandler]] = defaultdict(list)
        self._history: list[A2AMessage] = []
        self._pending: dict[str, asyncio.Future[A2AMessage]] = {}
        # Tracks the originating request's message id per correlation, so the
        # request's own publish does not satisfy its own pending future.
        self._pending_owner: dict[str, str] = {}
        self._lock = asyncio.Lock()

    async def subscribe(self, topic: str, handler: MessageHandler) -> None:
        self._subscribers[topic].append(handler)
        log.debug("bus.subscribe", topic=topic, handlers=len(self._subscribers[topic]))

    async def publish(self, message: A2AMessage) -> None:
        async with self._lock:
            self._history.append(message)

        # Resolve any pending request awaiting this correlation id — but never
        # with the originating request message itself (it shares the id).
        corr = message.correlation_id
        if (
            corr
            and corr in self._pending
            and self._pending_owner.get(corr) != message.id
        ):
            fut = self._pending.pop(corr)
            self._pending_owner.pop(corr, None)
            if not fut.done():
                fut.set_result(message)

        handlers = list(self._subscribers.get(message.topic, []))
        handlers += list(self._subscribers.get("*", []))  # wildcard observers
        log.debug(
            "bus.publish",
            topic=message.topic,
            sender=str(message.sender),
            recipient=str(message.recipient) if message.recipient else "broadcast",
            handlers=len(handlers),
        )
        # Dispatch concurrently; isolate handler failures.
        await asyncio.gather(
            *(self._safe_dispatch(h, message) for h in handlers), return_exceptions=True
        )

    async def _safe_dispatch(self, handler: MessageHandler, message: A2AMessage) -> None:
        try:
            await handler(message)
        except Exception as exc:  # noqa: BLE001 - never let one handler kill the bus
            log.error("bus.handler_error", error=str(exc), msg_id=message.id)

    async def request(self, message: A2AMessage, timeout: float = 60.0) -> A2AMessage:
        """Publish a message and await a response carrying the same correlation id."""
        corr = message.correlation_id or message.id
        message.correlation_id = corr
        loop = asyncio.get_running_loop()
        fut: asyncio.Future[A2AMessage] = loop.create_future()
        self._pending[corr] = fut
        self._pending_owner[corr] = message.id
        await self.publish(message)
        try:
            return await asyncio.wait_for(fut, timeout=timeout)
        finally:
            self._pending.pop(corr, None)
            self._pending_owner.pop(corr, None)

    def history(self) -> list[A2AMessage]:
        return list(self._history)
