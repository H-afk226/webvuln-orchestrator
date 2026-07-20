"""Scanner registry. Populated in Steps 4 and 5."""

from __future__ import annotations

from src.scanners.base import Scanner

REGISTRY: dict[str, type[Scanner]] = {}
