"""sqlmap scanner: focused SQL injection detection.

Unlike the broad scanners, sqlmap is a specialist. It is run in
detection-only mode with a crawl, never in exploitation mode --
the goal is measuring detection capability, not extracting data.
"""

from __future__ import annotations

import csv as _csv
import re
from pathlib import Path

from src.config import Target
from src.owasp import owasp_for_cwe
from src.scanners.base import Scanner
from src.schema import Confidence, Finding, Severity


class SqlmapScanner(Scanner):
    name = "sqlmap"
    default_timeout = 1800

    def version(self) -> str | None:
        try:
            out = self._run(["sqlmap", "--version"]).stdout
            m = re.search(r"([\d]+\.[\d.]+)", out)
            return m.group(1) if m else None
        except Exception:      # noqa: BLE001
            return None

    def _execute(self, target: Target) -> tuple[int, Path]:
        out_dir = self.run_dir / "sqlmap-out"
        raw = self.run_dir / "sqlmap.log"

        cmd = [
            "sqlmap",
            "-u", target.base_url,
            "--crawl", "2",
            "--batch",
            "--random-agent",
            "--level", "2",
            "--risk", "1",
            "--technique", "BEUST",
            "--output-dir", str(out_dir),
            "--flush-session",
            "--answers", "quit=N,crack=N,dict=N,continue=Y",
        ]
        if self.session:
            if self.session.cookies:
                cmd += ["--cookie", self.session.cookie_string]
            if self.session.token:
                cmd += ["--headers", f"Authorization: Bearer {self.session.token}"]

        proc = self._run(cmd)
        raw.write_text(proc.stdout + "\n--- STDERR ---\n" + proc.stderr)
        return proc.returncode, raw

    def _parse(self, raw_path: Path, target: Target) -> list[Finding]:
        findings: list[Finding] = []

        # Primary source: sqlmap's structured results CSV, if produced
        out_dir = raw_path.parent / "sqlmap-out"
        for csv_path in out_dir.rglob("*.csv"):
            try:
                for row in _csv.DictReader(csv_path.open(newline="")):
                    findings.append(self._make(target, str(row)))
            except Exception:      # noqa: BLE001
                continue

        if findings:
            return findings

        # Fallback: parse the console log for injection confirmations
        log = raw_path.read_text() if raw_path.exists() else ""
        for m in re.finditer(
            r"Parameter:\s*(\S+)\s*\(([^)]+)\).*?Type:\s*([^\n]+)", log, re.S
        ):
            param, method, itype = m.group(1), m.group(2), m.group(3).strip()
            findings.append(
                Finding(
                    tool=self.name,
                    target=target.name,
                    name=f"SQL injection ({itype})",
                    description=f"Parameter '{param}' is injectable via {itype}.",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,   # sqlmap verifies exploitability
                    cwe_id=89,
                    owasp_category=owasp_for_cwe(89),
                    url=target.base_url,
                    method=method.upper(),
                    param=param,
                    evidence=itype[:500],
                    raw_id="sqli",
                )
            )

        return findings

    def _make(self, target: Target, blob: str) -> Finding:
        return Finding(
            tool=self.name,
            target=target.name,
            name="SQL injection",
            description=blob[:2000],
            severity=Severity.CRITICAL,
            confidence=Confidence.CONFIRMED,
            cwe_id=89,
            owasp_category=owasp_for_cwe(89),
            url=target.base_url,
            evidence=blob[:500],
            raw_id="sqli",
        )
