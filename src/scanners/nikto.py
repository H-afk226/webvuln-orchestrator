"""Nikto scanner, driven as a subprocess with CSV output.

Nikto's JSON reporting plugin fails with a Perl module resolution
error even when libjson-perl is installed, so CSV is used instead.
"""

from __future__ import annotations

import csv as _csv
import re
from pathlib import Path
from urllib.parse import urlparse

from src.config import Target
from src.owasp import owasp_for_cwe
from src.scanners.base import Scanner
from src.schema import Confidence, Finding, Severity

# Nikto has no severity field, so severity is inferred from the message.
HIGH_PATTERNS = [
    r"\bSQL\b", r"remote file", r"command execution", r"shell",
    r"traversal", r"\bRCE\b", r"backdoor", r"password file",
]
MEDIUM_PATTERNS = [
    r"\bXSS\b", r"cross.?site", r"injection", r"disclosure",
    r"outdated", r"vulnerab", r"default (file|account)", r"admin",
    r"backup/cert file", r"non-forbidden", r"access-control-allow-origin.*\*",
    r"directory indexing|directory listing",
]

# Nikto reports OSVDB ids, not CWEs; map common message shapes instead.
MESSAGE_TO_CWE = [
    # Patterns derived from observed Nikto 2.5.0 output, not documentation.
    (r"access-control-allow-origin.*\*", 942),
    (r"uncommon header", 200),
    (r"backup/cert file|backup file", 530),
    (r"robots\.txt", 200),
    (r"clickjack|X-Frame-Options", 1021),
    (r"X-Content-Type-Options", 16),
    (r"Strict-Transport-Security", 319),
    (r"Content-Security-Policy", 16),
    (r"cookie.*without.*httponly", 1004),
    (r"cookie.*without.*secure", 614),
    (r"directory indexing|directory listing", 548),
    (r"traversal", 22),
    (r"\bSQL\b", 89),
    (r"\bXSS\b|cross.?site scripting", 79),
    (r"outdated|out of date|appears to be outdated", 1104),
    (r"TRACE|TRACK", 16),
    (r"server leaks|reveals|disclosure|inode", 200),
    (r"default (file|account|credential)", 1188),
    (r"non-forbidden|returned a.*200", 200),
    (r"admin|login page|phpmyadmin", 1188),
    (r"header.*not set|missing.*header", 693),
]


class NiktoScanner(Scanner):
    name = "nikto"
    default_timeout = 1200

    def version(self) -> str | None:
        try:
            out = self._run(["nikto", "-Version"]).stdout
            m = re.search(r"Nikto\s+([\d.]+)", out)
            return m.group(1) if m else None
        except Exception:      # noqa: BLE001
            return None

    def _execute(self, target: Target) -> tuple[int, Path]:
        parsed = urlparse(target.base_url)
        host = parsed.hostname or ""
        port = str(parsed.port or (443 if parsed.scheme == "https" else 80))
        raw = self.run_dir / "nikto.csv"

        cmd = [
            "nikto",
            "-h", host,
            "-p", port,
            "-Format", "csv",
            "-output", str(raw),
            "-nointeractive",
            "-ask", "no",
        ]
        if parsed.path and parsed.path != "/":
            cmd += ["-root", parsed.path]

        proc = self._run(cmd)
        if not raw.exists():
            raw.write_text("")
        return proc.returncode, raw

    @staticmethod
    def _severity_for(msg: str) -> Severity:
        for p in HIGH_PATTERNS:
            if re.search(p, msg, re.I):
                return Severity.HIGH
        for p in MEDIUM_PATTERNS:
            if re.search(p, msg, re.I):
                return Severity.MEDIUM
        return Severity.INFO

    @staticmethod
    def _cwe_for(msg: str) -> int | None:
        for pattern, cwe in MESSAGE_TO_CWE:
            if re.search(pattern, msg, re.I):
                return cwe
        return None

    def _parse(self, raw_path: Path, target: Target) -> list[Finding]:
        if not raw_path.exists():
            return []

        findings: list[Finding] = []
        with raw_path.open(newline="") as fh:
            for row in _csv.reader(fh):
                if len(row) < 7:
                    continue
                osvdb, method, uri, msg = row[3], row[4], row[5], row[6]
                if not msg or msg.lower().startswith("message"):
                    continue

                cwe_id = self._cwe_for(msg)
                url = target.base_url.rstrip("/") + "/" + (uri or "").lstrip("/")

                findings.append(
                    Finding(
                        tool=self.name,
                        target=target.name,
                        name=msg[:120],
                        description=msg[:2000],
                        severity=self._severity_for(msg),
                        confidence=Confidence.LOW,   # signature-based
                        cwe_id=cwe_id,
                        owasp_category=owasp_for_cwe(cwe_id),
                        url=url,
                        method=method or "GET",
                        raw_id=osvdb or None,
                    )
                )
        return findings
