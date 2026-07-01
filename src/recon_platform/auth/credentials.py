"""Secure credential handling for the authentication agent.

Credentials are read from :class:`~recon_platform.core.config.AuthSettings` (env
``RECON_AUTH__*``, password held as ``SecretStr``) into a small holder that
exposes the plaintext only on explicit access and provides a masking helper so the
agent can surface *that* it used credentials without ever revealing them.
"""

from __future__ import annotations

from dataclasses import dataclass

from recon_platform.core.config import Settings


def mask(value: str) -> str:
    """Mask a credential for evidence/traces: never reveal the plaintext."""
    if not value:
        return "—"
    return f"{value[0]}{'•' * (len(value) - 1)}" if len(value) > 1 else "•"


@dataclass
class Credentials:
    """Plaintext credentials, obtained just-in-time from settings."""

    username: str = ""
    password: str = ""
    email: str = ""

    @property
    def has_login(self) -> bool:
        return bool((self.username or self.email) and self.password)

    @property
    def has_registration(self) -> bool:
        return bool(self.email and self.password)

    def masked(self) -> dict[str, str]:
        return {
            "username": mask(self.username),
            "password": mask(self.password),
            "email": mask(self.email),
        }


def credentials_from_settings(settings: Settings) -> Credentials:
    """Build a :class:`Credentials` from ``settings.auth`` (unwrapping SecretStr)."""
    auth = settings.auth
    return Credentials(
        username=auth.username,
        password=auth.password.get_secret_value(),
        email=auth.email,
    )
