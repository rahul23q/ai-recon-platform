"""Value objects for the authentication agent.

Plain dataclasses (not graph assets) so workflows can return rich results the
agent then normalizes into a masked ``SESSION`` asset + an episodic-memory record.
Cookie *values* live only in :class:`CapturedSession` (kept in episodic memory for
downstream reuse); the graph asset records only cookie *names*.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class CapturedSession:
    """An authenticated session captured for downstream reuse.

    ``cookies`` holds the full cookie dicts (with values) — sensitive, so it is
    stored only in episodic memory, never on a graph asset or in a report.
    """

    workflow: str
    url: str
    cookies: list[dict] = field(default_factory=list)

    @property
    def cookie_names(self) -> list[str]:
        return sorted({str(c.get("name", "")) for c in self.cookies if c.get("name")})


@dataclass
class AuthResult:
    """The outcome of one attempted authentication workflow."""

    workflow: str
    url: str = ""
    success: bool = False
    reason: str = ""
    scheme: str = ""  # http | https (of the submitted URL)
    session: CapturedSession | None = None
    # Workflow-specific extras (e.g. admin probe's ``accessible_unauthenticated``).
    detail: dict = field(default_factory=dict)
    error: str = ""
