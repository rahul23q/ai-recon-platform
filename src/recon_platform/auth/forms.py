"""Pure form/field heuristics for the authentication workflows.

Deterministic and dependency-free: given lightweight descriptors of a page's
input fields (name / type / id / placeholder / autocomplete), classify each field
and locate the username / email / password / submit controls; and, given a
before/after snapshot of a submit, decide whether authentication succeeded. The
Playwright-backed page adapter feeds these functions the field descriptors it
scrapes, so all the logic here is directly unit-testable without a browser.
"""

from __future__ import annotations

from dataclasses import dataclass

_USERNAME_HINTS = ("user", "login", "account", "uid", "loginid", "identifier")
_EMAIL_HINTS = ("email", "e-mail", "mail")
_PASSWORD_CONFIRM_HINTS = ("confirm", "repeat", "verify", "retype", "again", "password2")
# Cookie-name fragments that indicate an authenticated session was established.
_SESSION_COOKIE_HINTS = ("session", "sess", "auth", "token", "jwt", "sid", "login", "remember")
# Text fragments that indicate a failed login.
_FAILURE_HINTS = (
    "invalid", "incorrect", "failed", "try again", "wrong", "not recognized",
    "bad credentials", "authentication failed", "does not match",
)


@dataclass
class FieldInfo:
    """A lightweight descriptor of one form input."""

    name: str = ""
    field_type: str = ""
    field_id: str = ""
    placeholder: str = ""
    autocomplete: str = ""

    def _haystack(self) -> str:
        return " ".join(
            [self.name, self.field_id, self.placeholder, self.autocomplete]
        ).lower()


@dataclass
class FieldMap:
    """The located controls of an auth form (CSS selectors, or ``None``)."""

    username: str | None = None
    email: str | None = None
    password: str | None = None
    password_confirm: str | None = None
    submit: str | None = None

    @property
    def has_password(self) -> bool:
        return self.password is not None


def field_selector(field: FieldInfo) -> str | None:
    """Return a stable CSS selector for a field (prefer name, then id)."""
    if field.name:
        return f'[name="{field.name}"]'
    if field.field_id:
        return f"#{field.field_id}"
    return None


def classify_field(field: FieldInfo) -> str:
    """Classify a field as password / email / username / submit / other."""
    ftype = field.field_type.lower()
    hay = field._haystack()
    if ftype == "password":
        return "password"
    if ftype in ("submit", "button", "image"):
        return "submit"
    if ftype == "email" or "email" in field.autocomplete.lower() or any(
        h in hay for h in _EMAIL_HINTS
    ):
        return "email"
    if ftype in ("text", "") and any(h in hay for h in _USERNAME_HINTS):
        return "username"
    return "other"


def locate_fields(fields: list[FieldInfo]) -> FieldMap:
    """Locate the username / email / password(+confirm) / submit controls."""
    fmap = FieldMap()
    for field in fields:
        role = classify_field(field)
        selector = field_selector(field)
        if selector is None:
            continue
        if role == "password":
            if fmap.password is None:
                fmap.password = selector
            elif fmap.password_confirm is None and any(
                h in field._haystack() for h in _PASSWORD_CONFIRM_HINTS
            ):
                fmap.password_confirm = selector
            elif fmap.password_confirm is None:
                fmap.password_confirm = selector
        elif role == "email" and fmap.email is None:
            fmap.email = selector
        elif role == "username" and fmap.username is None:
            fmap.username = selector
        elif role == "submit" and fmap.submit is None:
            fmap.submit = selector
    return fmap


def is_session_cookie(name: str) -> bool:
    """True when a cookie name looks like an authenticated-session cookie."""
    low = name.lower()
    return any(h in low for h in _SESSION_COOKIE_HINTS)


def login_succeeded(
    *,
    before_url: str,
    after_url: str,
    cookie_names_before: list[str],
    cookie_names_after: list[str],
    form_present_after: bool,
    page_text_after: str = "",
) -> tuple[bool, str]:
    """Heuristically decide whether a login submission succeeded.

    Signals, strongest first: an explicit failure message ⇒ failure; a *new*
    session-looking cookie ⇒ success; navigation away from the login page with no
    login form remaining ⇒ success; otherwise (form still present) ⇒ failure.
    """
    text = (page_text_after or "").lower()
    if any(h in text for h in _FAILURE_HINTS):
        return False, "failure message shown on page"

    new_cookies = set(cookie_names_after) - set(cookie_names_before)
    if any(is_session_cookie(c) for c in new_cookies):
        return True, "new session cookie set"

    if after_url and after_url != before_url and not form_present_after:
        return True, "navigated away from login form"

    if not form_present_after and cookie_names_after != cookie_names_before:
        return True, "login form gone and cookies changed"

    return False, "login form still present / no session established"
