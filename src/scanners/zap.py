"""OWASP ZAP scanner, driven over the ZAP REST API.

ZAP runs as a long-lived service (see docker-compose.yml). We drive it
via HTTP rather than shelling out, which is how ZAP is used in real
DAST automation.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import requests

from src.config import Target
from src.owasp import owasp_for_cwe
from src.scanners.base import Scanner
from src.schema import Confidence, Finding, Severity

# ZAP 2.17's /core/view/alerts/ returns string labels ("risk", "confidence"),
# not the numeric riskcode/confidence codes documented for older versions.
ZAP_RISK_TO_SEVERITY = {
    "informational": Severity.INFO,
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}

ZAP_CONFIDENCE = {
    "false positive": Confidence.LOW,
    "low": Confidence.LOW,
    "medium": Confidence.MEDIUM,
    "high": Confidence.HIGH,
    "confirmed": Confidence.CONFIRMED,
}


class ZapScanner(Scanner):
    name = "zap"
    default_timeout = 1800

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        host = os.environ.get("ZAP_HOST", "zap")
        port = os.environ.get("ZAP_PORT", "8090")
        self.api_key = os.environ.get("ZAP_API_KEY", "changeme")
        self.base = f"http://{host}:{port}"

    # ---- API helpers -------------------------------------------------
    def _api(self, path: str, **params) -> dict:
        params["apikey"] = self.api_key
        r = requests.get(f"{self.base}/JSON/{path}", params=params, timeout=300)
        r.raise_for_status()
        return r.json()

    def version(self) -> str | None:
        try:
            return self._api("core/view/version/").get("version")
        except Exception:      # noqa: BLE001
            return None

    def _wait(self, poll: callable, label: str) -> None:
        """Block until a ZAP job reports 100%, respecting the timeout."""
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            status = int(poll())
            if status >= 100:
                return
            time.sleep(3)
        raise TimeoutError(f"ZAP {label} did not finish within {self.timeout}s")

    # ---- Scanner interface -------------------------------------------
    def _execute(self, target: Target) -> tuple[int, Path]:
        url = target.base_url

        # Fresh session so runs don't contaminate each other
        self._api("core/action/newSession/", name=f"scan-{target.name}", overwrite="true")

        # Spider: discover the attack surface
        spider_id = self._api("spider/action/scan/", url=url, recurse="true")["scan"]
        self._wait(
            lambda: self._api("spider/view/status/", scanId=spider_id)["status"],
            "spider",
        )

        # Passive scan queue must drain before results are complete
        deadline = time.time() + 120
        while time.time() < deadline:
            remaining = int(self._api("pscan/view/recordsToScan/")["recordsToScan"])
            if remaining == 0:
                break
            time.sleep(2)

        # Active scan: actually attack the discovered endpoints
        ascan_id = self._api("ascan/action/scan/", url=url, recurse="true")["scan"]
        self._wait(
            lambda: self._api("ascan/view/status/", scanId=ascan_id)["status"],
            "active scan",
        )

        alerts = self._api("core/view/alerts/", baseurl=url, start="0", count="9999")
        raw = self.run_dir / "zap-alerts.json"
        raw.write_text(json.dumps(alerts, indent=2))
        return 0, raw

    def _parse(self, raw_path: Path, target: Target) -> list[Finding]:
        data = json.loads(raw_path.read_text())
        findings: list[Finding] = []

        for alert in data.get("alerts", []):
            cwe = alert.get("cweid")
            try:
                cwe_id = int(cwe) if cwe and int(cwe) > 0 else None
            except (TypeError, ValueError):
                cwe_id = None

            findings.append(
                Finding(
                    tool=self.name,
                    target=target.name,
                    name=alert.get("alert") or alert.get("name") or "unknown",
                    description=(alert.get("description") or "")[:2000],
                    severity=ZAP_RISK_TO_SEVERITY.get(
                        str(alert.get("risk", "")).strip().lower(), Severity.INFO
                    ),
                    confidence=ZAP_CONFIDENCE.get(
                        str(alert.get("confidence", "")).strip().lower(),
                        Confidence.MEDIUM,
                    ),
                    cwe_id=cwe_id,
                    owasp_category=owasp_for_cwe(cwe_id),
                    url=alert.get("url", ""),
                    method=alert.get("method"),
                    param=alert.get("param") or None,
                    evidence=(alert.get("evidence") or "")[:500] or None,
                    solution=(alert.get("solution") or "")[:1000] or None,
                    raw_id=str(alert.get("pluginId") or ""),
                )
            )
        return findings
