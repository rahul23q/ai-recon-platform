"""A2A message bus tests."""

from __future__ import annotations

import asyncio

from recon_platform.a2a.bus import InMemoryMessageBus
from recon_platform.domain.enums import AgentRole
from recon_platform.domain.schemas import A2AMessage


async def test_publish_subscribe_delivers_to_topic():
    bus = InMemoryMessageBus()
    received: list[A2AMessage] = []

    async def handler(msg: A2AMessage) -> None:
        received.append(msg)

    await bus.subscribe("timeline", handler)
    await bus.publish(A2AMessage(sender=AgentRole.PLANNER, topic="timeline", reason="hi"))

    assert len(received) == 1
    assert received[0].reason == "hi"
    assert len(bus.history()) == 1


async def test_request_response_correlation():
    bus = InMemoryMessageBus()

    async def responder(msg: A2AMessage) -> None:
        if msg.sender == AgentRole.PLANNER:
            await bus.publish(
                A2AMessage(
                    sender=AgentRole.RECON,
                    topic="reply",
                    correlation_id=msg.correlation_id,
                    reason="done",
                )
            )

    await bus.subscribe("reply", responder)
    request = A2AMessage(sender=AgentRole.PLANNER, topic="reply")
    response = await asyncio.wait_for(bus.request(request, timeout=2.0), timeout=3.0)
    assert response.reason == "done"
    assert response.correlation_id == request.correlation_id
