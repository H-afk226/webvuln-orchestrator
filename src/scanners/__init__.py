"""Scanner registry.

Adding a scanner means writing one Scanner subclass and adding one
entry here. Nothing else in the codebase changes.
"""

from __future__ import annotations

from src.scanners.base import Scanner
from src.scanners.nikto import NiktoScanner
from src.scanners.zap import ZapScanner

REGISTRY: dict[str, type[Scanner]] = {
    "zap": ZapScanner,
    "nikto": NiktoScanner,
}
