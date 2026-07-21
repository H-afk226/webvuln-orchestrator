"""Scanner registry.

Adding a scanner means writing one Scanner subclass and adding one
entry here. Nothing else in the codebase changes -- the CLI,
correlation engine and reporting layer only ever see ScanResult.
"""

from __future__ import annotations

from src.scanners.base import Scanner
from src.scanners.nikto import NiktoScanner
from src.scanners.nmap import NmapScanner
from src.scanners.sqlmap import SqlmapScanner
from src.scanners.testssl import TestsslScanner
from src.scanners.wapiti import WapitiScanner
from src.scanners.zap import ZapScanner

REGISTRY: dict[str, type[Scanner]] = {
    "nmap": NmapScanner,
    "zap": ZapScanner,
    "nikto": NiktoScanner,
    "wapiti": WapitiScanner,
    "sqlmap": SqlmapScanner,
    "testssl": TestsslScanner,
}
