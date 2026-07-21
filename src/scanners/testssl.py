"""testssl.sh scanner: TLS/SSL configuration assessment.

Only meaningful against HTTPS endpoints. Against plain HTTP targets
it correctly reports nothing, which is itself a finding worth
recording: the lab targets serve unencrypted traffic.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlparse

from src.config import Target
from src.owasp import owasp_for_cwe
from src.scanners.base import Scanner
from src.schema import Confidence, Finding, Severity

TESTSSL_SEVERITY = {
    "OK": Severity.INFO,
    "INFO": Severity.INFO,
    "LOW": Severity.LOW,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
    "WARN": Severity.LOW,
    "DEBUG": Severity.INFO,
}

# testssl finding id -> CWE
ID_TO_CWE = [
    (r"^(SSLv2|SSLv3|TLS1$|TLS1_1)", 327),
    (r"cipher|RC4|3DES|DES|NULL|EXPORT", 327),
    (r"heartbleed|ROBOT|CCS|ticketbleed|BREACH|POODLE|FREAK|DROWN|LOGJAM|BEAST|SWEET32", 327),
    (r"cert_expiration|cert_notAfter|cert_notBefore", 295),
    (r"cert_chain|cert_trust|cert_caIssuers", 295),
    (r"HSTS|hsts", 319),
    (r"fallback|renegotiation", 326),
    (r"secure_client_renego", 326),
]


class TestsslScanner(Scanner):
    name = "testssl"
    default_timeout = 1200

    def version(self) -> str | None:
        try:
            out = self._run(["testssl.sh", "--version"]).stdout
            m = re.search(r"version\s+([\d.]+)", out)
            return m.group(1) if m else None
        except Exception:      # noqa: BLE001
            return None

    def _execute(self, target: Target) -> tuple[int, Path]:
        parsed = urlparse(target.base_url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        raw = self.run_dir / "testssl.json"

        # Skip non-TLS targets: probing a plain HTTP port makes testssl
        # run its full battery against a service that never completes a
        # handshake, costing ~20 minutes to discover there is no TLS.
        if parsed.scheme != "https":
            raw.write_text("[]")
            return 0, raw

        cmd = [
            "testssl.sh",
            "--jsonfile", str(raw),
            "--quiet",
            "--color", "0",
            "--severity", "LOW",
            "--openssl-timeout", "10",
            f"{host}:{port}",
        ]
        proc = self._run(cmd)
        if not raw.exists():
            raw.write_text("[]")
        return proc.returncode, raw

    @staticmethod
    def _cwe_for(finding_id: str) -> int | None:
        for pattern, cwe in ID_TO_CWE:
            if re.search(pattern, finding_id, re.I):
                return cwe
        return None

    def _parse(self, raw_path: Path, target: Target) -> list[Finding]:
        text = raw_path.read_text().strip()
        if not text:
            return []

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return []

        entries = data if isinstance(data, list) else data.get("scanResult", [])
        findings: list[Finding] = []

        for e in entries:
            if not isinstance(e, dict):
                continue
            fid = e.get("id", "")
            sev_raw = str(e.get("severity", "INFO")).upper()
            sev = TESTSSL_SEVERITY.get(sev_raw, Severity.INFO)

            if sev == Severity.INFO and sev_raw == "OK":
                continue

            cwe_id = self._cwe_for(fid)
            findings.append(
                Finding(
                    tool=self.name,
                    target=target.name,
                    name=fid or "tls finding",
                    description=str(e.get("finding", ""))[:2000],
                    severity=sev,
                    confidence=Confidence.HIGH,   # config facts, not heuristics
                    cwe_id=cwe_id,
                    owasp_category=owasp_for_cwe(cwe_id),
                    url=target.base_url,
                    evidence=str(e.get("finding", ""))[:500] or None,
                    raw_id=fid,
                )
            )

        return findings
