"""In-memory implementation of the layered `Memory` Protocol.

Holds four scopes (short-term / working / long-term / episodic) plus a flat
reasoning-trace log. Substantive backends (Redis for working memory, a vector
store for semantic recall, SQLite/Postgres for long-term) implement the same
Protocol and swap in via the DI container.

`search` is a simple substring match here; a vector-memory implementation would
override it with embeddings + similarity.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import Any

from recon_platform.domain.enums import MemoryScope
from recon_platform.domain.schemas import ReasoningTrace


class InMemoryMemory:
    """Process-local layered memory."""

    def __init__(self) -> None:
        self._store: dict[MemoryScope, dict[str, Any]] = defaultdict(dict)
        self._traces: list[ReasoningTrace] = []
        self._lock = asyncio.Lock()

    async def remember(self, scope: MemoryScope, key: str, value: Any) -> None:
        async with self._lock:
            self._store[scope][key] = value

    async def recall(self, scope: MemoryScope, key: str) -> Any | None:
        return self._store.get(scope, {}).get(key)

    async def search(self, scope: MemoryScope, query: str) -> list[Any]:
        q = query.lower()
        return [
            v
            for k, v in self._store.get(scope, {}).items()
            if q in k.lower() or q in str(v).lower()
        ]

    async def append_trace(self, trace: ReasoningTrace) -> None:
        async with self._lock:
            self._traces.append(trace)

    def traces(self) -> list[ReasoningTrace]:
        return list(self._traces)
