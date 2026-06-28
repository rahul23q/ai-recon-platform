"""Exception hierarchy for the platform.

A single root (`ReconPlatformError`) lets callers catch everything domain-specific
while still distinguishing categories. Keep these free of heavy imports.
"""

from __future__ import annotations


class ReconPlatformError(Exception):
    """Base class for all platform-specific errors."""


class ConfigurationError(ReconPlatformError):
    """Invalid or missing configuration."""


class UnauthorizedTargetError(ReconPlatformError):
    """Raised when a target fails the authorization gate.

    The platform is for authorized testing only; this guards accidental scans.
    """


class AgentError(ReconPlatformError):
    """An agent failed to complete its task."""


class PluginError(ReconPlatformError):
    """A plugin could not be loaded or validated."""


class ToolExecutionError(ReconPlatformError):
    """A tool/plugin failed at runtime."""

    def __init__(self, tool: str, message: str) -> None:
        self.tool = tool
        super().__init__(f"[{tool}] {message}")


class MemoryError_(ReconPlatformError):
    """Memory subsystem failure (named with underscore to avoid the builtin)."""


class DependencyResolutionError(ReconPlatformError):
    """The DI container could not resolve a requested dependency."""
