"""Nmap scanner: port and service discovery, plus NSE http scripts.

Nmap is not a web vulnerability scanner, but it establishes the
attack surface (open ports, service versions) that the DAST tools
then operate against.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse

from src.config import Target
from src.owasp import owasp_for_cwe
from src.scanners.base import Scanner
from src.schema import Confidence, Finding, Severity


class NmapScanner(Scanner):
    name = "nmap"
    default_timeout = 900

    def version(self) -> str | None:
        try:
            out = self._run(["nmap", "--version"]).stdout
            m = re.search(r"Nmap version ([\d.]+)", out)
            return m.group(1) if m else None
        except Exception:      # noqa: BLE001
            return None

    def _execute(self, target: Target) -> tuple[int, Path]:
        parsed = urlparse(target.base_url)
        host = parsed.hostname or ""
        port = str(parsed.port or (443 if parsed.scheme == "https" else 80))
        raw = self.run_dir / "nmap.xml"

        # -sT connect scan: no NET_RAW capability needed inside the container,
        # which keeps the image runnable without elevated privileges.
        cmd = [
            "nmap", "-sT", "-sV",
            "-p", port,
            "--script", "http-headers,http-methods,http-title,http-server-header",
            "-oX", str(raw),
            host,
        ]
        proc = self._run(cmd)
        return proc.returncode, raw

    def _parse(self, raw_path: Path, target: Target) -> list[Finding]:
        if not raw_path.exists() or not raw_path.read_text().strip():
            return []

        try:
            root = ET.parse(raw_path).getroot()
        except ET.ParseError:
            return []

        findings: list[Finding] = []

        for host in root.iter("host"):
            for port in host.iter("port"):
                portid = port.get("portid", "")
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue

                svc = port.find("service")
                product = (svc.get("product", "") if svc is not None else "")
                ver = (svc.get("version", "") if svc is not None else "")
                banner = " ".join(x for x in (product, ver) if x).strip()

                # Service version disclosure -> CWE-200
                if banner:
                    findings.append(
                        Finding(
                            tool=self.name,
                            target=target.name,
                            name=f"Service banner disclosed on port {portid}",
                            description=f"Service identified as: {banner}",
                            severity=Severity.LOW,
                            confidence=Confidence.HIGH,
                            cwe_id=200,
                            owasp_category=owasp_for_cwe(200),
                            url=target.base_url,
                            evidence=banner,
                            raw_id=f"port-{portid}",
                        )
                    )

                for script in port.iter("script"):
                    sid = script.get("id", "")
                    out = (script.get("output") or "").strip()
                    if not out:
                        continue

                    cwe_id = None
                    sev = Severity.INFO
                    if sid == "http-methods" and re.search(r"TRACE|PUT|DELETE", out):
                        cwe_id, sev = 16, Severity.MEDIUM
                    elif sid in ("http-server-header", "http-headers"):
                        cwe_id = 200

                    findings.append(
                        Finding(
                            tool=self.name,
                            target=target.name,
                            name=f"NSE {sid}",
                            description=out[:2000],
                            severity=sev,
                            confidence=Confidence.MEDIUM,
                            cwe_id=cwe_id,
                            owasp_category=owasp_for_cwe(cwe_id),
                            url=target.base_url,
                            evidence=out[:500],
                            raw_id=sid,
                        )
                    )

        return findings
