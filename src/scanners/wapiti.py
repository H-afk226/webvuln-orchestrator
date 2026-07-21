"""Wapiti scanner: active DAST with structured JSON output.

Wapiti is the natural comparison point for ZAP: both are active
scanners that crawl and attack, so overlap between them is the
clearest test of the cross-tool correlation logic.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from src.config import Target
from src.owasp import owasp_for_cwe
from src.scanners.base import Scanner
from src.schema import Confidence, Finding, Severity

# Wapiti module name -> (CWE, severity)
WAPITI_MODULE_MAP: dict[str, tuple[int | None, Severity]] = {
    "Blind SQL Injection": (89, Severity.HIGH),
    "SQL Injection": (89, Severity.HIGH),
    "Cross Site Scripting": (79, Severity.HIGH),
    "Reflected Cross Site Scripting": (79, Severity.HIGH),
    "Stored Cross Site Scripting": (79, Severity.HIGH),
    "Command execution": (78, Severity.CRITICAL),
    "Path Traversal": (22, Severity.HIGH),
    "CRLF Injection": (93, Severity.MEDIUM),
    "Server Side Request Forgery": (918, Severity.HIGH),
    "XML External Entity": (611, Severity.HIGH),
    "Cross Site Request Forgery": (352, Severity.MEDIUM),
    "Open Redirect": (601, Severity.MEDIUM),
    "Secure Flag cookie": (614, Severity.LOW),
    "HttpOnly Flag cookie": (1004, Severity.LOW),
    "Content Security Policy Configuration": (693, Severity.LOW),
    "HTTP Secure Headers": (693, Severity.LOW),
    "Backup file": (530, Severity.MEDIUM),
    "Potentially dangerous file": (530, Severity.MEDIUM),
    "Fingerprint web technology": (200, Severity.INFO),
    "Fingerprint web server": (200, Severity.INFO),
}

WAPITI_LEVEL_TO_SEVERITY = {
    1: Severity.LOW,
    2: Severity.MEDIUM,
    3: Severity.HIGH,
    4: Severity.CRITICAL,
}


class WapitiScanner(Scanner):
    name = "wapiti"
    default_timeout = 2400

    def version(self) -> str | None:
        try:
            out = self._run(["wapiti", "--version"]).stdout
            m = re.search(r"([\d]+\.[\d.]+)", out)
            return m.group(1) if m else None
        except Exception:      # noqa: BLE001
            return None

    def _execute(self, target: Target) -> tuple[int, Path]:
        raw = self.run_dir / "wapiti.json"
        cmd = [
            "wapiti",
            "-u", target.base_url,
            "-f", "json",
            "-o", str(raw),
            "--flush-session",
            "--max-scan-time", str(self.timeout - 120),
            "--scope", "folder",
            "--verify-ssl", "0",
        ]
        proc = self._run(cmd)
        if not raw.exists():
            raw.write_text(json.dumps({"vulnerabilities": {}}))
        return proc.returncode, raw

    def _parse(self, raw_path: Path, target: Target) -> list[Finding]:
        text = raw_path.read_text().strip()
        if not text:
            return []

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return []

        findings: list[Finding] = []
        vulns = data.get("vulnerabilities", {}) or {}

        for category, entries in vulns.items():
            if not entries:
                continue
            cwe_id, default_sev = WAPITI_MODULE_MAP.get(category, (None, Severity.INFO))

            for e in entries:
                level = e.get("level")
                sev = WAPITI_LEVEL_TO_SEVERITY.get(level, default_sev)

                findings.append(
                    Finding(
                        tool=self.name,
                        target=target.name,
                        name=category,
                        description=(e.get("info") or category)[:2000],
                        severity=sev,
                        confidence=Confidence.MEDIUM,
                        cwe_id=cwe_id,
                        owasp_category=owasp_for_cwe(cwe_id),
                        url=e.get("path") or target.base_url,
                        method=e.get("method") or "GET",
                        param=e.get("parameter") or None,
                        evidence=(e.get("http_request") or "")[:500] or None,
                        solution=(e.get("solution") or "")[:1000] or None,
                        raw_id=category,
                    )
                )

        return findings
