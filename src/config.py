"""Target configuration and scope enforcement."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel

CONFIG_PATH = Path("/app/config/targets.yml")


class ScopeViolation(Exception):
    """Raised when a scan is requested against a target outside the allowlist."""


class AuthConfig(BaseModel):
    """Credentials and mechanism for authenticating to a target."""

    type: str                      # "form" | "json"
    login_url: str
    username: str
    password: str
    username_field: str = "username"
    password_field: str = "password"
    extra_fields: dict[str, str] = {}
    csrf_field: str | None = None
    logged_in_indicator: str | None = None
    token_path: str | None = None  # dotted path into a JSON login response


class Target(BaseModel):
    name: str
    base_url: str
    tech: str = ""
    seed_urls: list[str] = []
    auth: AuthConfig | None = None


class TargetConfig(BaseModel):
    allowlist: list[str]
    targets: dict[str, Target]

    def get(self, name: str) -> Target:
        """Return a target, refusing anything not explicitly allowlisted."""
        if name not in self.allowlist:
            raise ScopeViolation(
                f"'{name}' is not in the scope allowlist. "
                f"Permitted targets: {', '.join(sorted(self.allowlist))}"
            )
        if name not in self.targets:
            raise ScopeViolation(f"'{name}' is allowlisted but has no definition.")
        return self.targets[name]

    def all_names(self) -> list[str]:
        return [n for n in self.allowlist if n in self.targets]


def load_config(path: Path = CONFIG_PATH) -> TargetConfig:
    if not path.exists():
        raise FileNotFoundError(f"Target config not found at {path}")

    data = yaml.safe_load(path.read_text())
    targets = {
        name: Target(name=name, **spec)
        for name, spec in (data.get("targets") or {}).items()
    }
    return TargetConfig(allowlist=data.get("allowlist", []), targets=targets)
