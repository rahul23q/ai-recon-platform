"""A small, typed dependency-injection container.

Deliberately dependency-free and explicit. Components are registered as either
singletons (instantiated once, lazily) or factories (new instance per resolve).
Resolution is by type, which keeps wiring discoverable and testable: swap any
implementation by re-registering its Protocol/base type.

Example::

    container = Container()
    container.register_singleton(MessageBus, lambda c: InMemoryMessageBus())
    bus = container.resolve(MessageBus)
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

from recon_platform.core.exceptions import DependencyResolutionError

T = TypeVar("T")

# A provider receives the container (for transitive resolution) and returns an
# instance of the registered type.
Provider = Callable[["Container"], object]


class Container:
    """Minimal service container with singleton + factory registration."""

    def __init__(self) -> None:
        self._singletons: dict[type, Provider] = {}
        self._factories: dict[type, Provider] = {}
        self._instances: dict[type, object] = {}

    def register_singleton(self, key: type[T], provider: Provider) -> None:
        """Register a provider whose result is cached after first resolution."""
        self._singletons[key] = provider
        self._instances.pop(key, None)

    def register_instance(self, key: type[T], instance: T) -> None:
        """Register an already-constructed instance as a singleton."""
        self._singletons[key] = lambda _c: instance
        self._instances[key] = instance

    def register_factory(self, key: type[T], provider: Provider) -> None:
        """Register a provider that produces a new instance on every resolve."""
        self._factories[key] = provider

    def resolve(self, key: type[T]) -> T:
        """Resolve an instance for ``key`` or raise DependencyResolutionError."""
        if key in self._instances:
            return self._instances[key]  # type: ignore[return-value]

        if key in self._singletons:
            instance = self._singletons[key](self)
            self._instances[key] = instance
            return instance  # type: ignore[return-value]

        if key in self._factories:
            return self._factories[key](self)  # type: ignore[return-value]

        raise DependencyResolutionError(
            f"No provider registered for {key.__module__}.{key.__qualname__}"
        )

    def has(self, key: type) -> bool:
        return key in self._singletons or key in self._factories or key in self._instances
