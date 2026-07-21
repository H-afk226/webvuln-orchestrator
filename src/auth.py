"""Session acquisition for authenticated scanning.

Produces either a cookie jar (form login) or a bearer token (JSON
login), which scanners then reuse. Authentication is verified before
scanning begins: an unverified session silently produces the same
result as no session at all, which is the failure mode this module
exists to prevent.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import requests

from src.config import AuthConfig, Target


class AuthenticationError(Exception):
    """Raised when a session could not be established or verified."""


@dataclass
class Session:
    """An authenticated session, in whichever form the target uses."""

    cookies: dict[str, str] = field(default_factory=dict)
    token: str | None = None
    header_name: str = "Authorization"

    @property
    def headers(self) -> dict[str, str]:
        return {self.header_name: f"Bearer {self.token}"} if self.token else {}

    @property
    def cookie_string(self) -> str:
        return "; ".join(f"{k}={v}" for k, v in self.cookies.items())

    def describe(self) -> str:
        if self.token:
            return f"bearer token ({len(self.token)} chars)"
        return f"cookies: {', '.join(self.cookies) or 'none'}"


def _dig(data: dict, dotted: str):
    """Walk a dotted path into nested dicts, e.g. 'authentication.token'."""
    cur = data
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _form_login(cfg: AuthConfig) -> Session:
    s = requests.Session()

    # Fetch the login page first: needed for the initial cookie and,
    # where present, a per-session CSRF token.
    page = s.get(cfg.login_url, timeout=30)

    payload = {
        cfg.username_field: cfg.username,
        cfg.password_field: cfg.password,
        **cfg.extra_fields,
    }

    if cfg.csrf_field:
        m = re.search(
            rf"name=['\"]{re.escape(cfg.csrf_field)}['\"]\s+value=['\"]([^'\"]+)['\"]",
            page.text,
        )
        if not m:
            m = re.search(
                rf"value=['\"]([^'\"]+)['\"]\s+name=['\"]{re.escape(cfg.csrf_field)}['\"]",
                page.text,
            )
        if not m:
            raise AuthenticationError(
                f"CSRF field '{cfg.csrf_field}' not found on {cfg.login_url}"
            )
        payload[cfg.csrf_field] = m.group(1)

    resp = s.post(cfg.login_url, data=payload, timeout=30, allow_redirects=True)

    if cfg.logged_in_indicator and cfg.logged_in_indicator not in resp.text:
        # Follow one redirect manually in case the indicator is on the landing page
        raise AuthenticationError(
            f"Login to {cfg.login_url} did not produce "
            f"'{cfg.logged_in_indicator}' in the response"
        )

    cookies = {c.name: c.value for c in s.cookies}
    if not cookies:
        raise AuthenticationError(f"No cookies set after login to {cfg.login_url}")

    return Session(cookies=cookies)


def _json_login(cfg: AuthConfig) -> Session:
    payload = {cfg.username_field: cfg.username, cfg.password_field: cfg.password}
    resp = requests.post(cfg.login_url, json=payload, timeout=30)

    if resp.status_code >= 400:
        raise AuthenticationError(
            f"Login to {cfg.login_url} returned HTTP {resp.status_code}"
        )

    try:
        data = resp.json()
    except ValueError as exc:
        raise AuthenticationError(f"Login response was not JSON: {exc}") from exc

    token = _dig(data, cfg.token_path) if cfg.token_path else None
    if not token:
        raise AuthenticationError(
            f"No token at path '{cfg.token_path}' in login response"
        )

    cookies = {c.name: c.value for c in resp.cookies}
    return Session(token=token, cookies=cookies)


def authenticate(target: Target) -> Session | None:
    """Establish a session for a target, or None if it needs no auth."""
    if not target.auth:
        return None

    if target.auth.type == "form":
        return _form_login(target.auth)
    if target.auth.type == "json":
        return _json_login(target.auth)

    raise AuthenticationError(f"Unknown auth type: {target.auth.type}")
