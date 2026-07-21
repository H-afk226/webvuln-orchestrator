"""Normalized data model shared by every scanner.

Each tool speaks its own dialect (XML, JSON, plain text, custom).
Everything is converted into the Finding model below so results
from different tools can be compared, deduplicated and scored
on equal terms.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import ClassVar
from urllib.parse import urlparse, urlunparse

from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {
            "informational": 0,
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }[self.value]


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"


class Finding(BaseModel):
    """A single normalized vulnerability finding."""

    tool: str
    tool_version: str | None = None
    target: str                      # logical name, e.g. "juiceshop"
    name: str
    description: str = ""
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.MEDIUM

    cwe_id: int | None = None
    owasp_category: str | None = None   # e.g. "A03:2021-Injection"

    url: str = ""
    method: str | None = None
    param: str | None = None
    evidence: str | None = None
    solution: str | None = None

    raw_id: str | None = None           # tool's own identifier
    discovered_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    # ------------------------------------------------------------------
    # Correlation
    # ------------------------------------------------------------------
    @staticmethod
    def _normalize_url(url: str) -> str:
        """Strip query, fragment and trailing slash so the same endpoint
        reported by two tools produces the same fingerprint."""
        if not url:
            return ""
        p = urlparse(url)
        path = p.path.rstrip("/") or "/"
        return urlunparse((p.scheme, p.netloc, path, "", "", ""))

    @property
    def fingerprint(self) -> str:
        """Stable hash identifying the *vulnerability*, not the report of it.

        Deliberately excludes `tool`, so that when two scanners find the
        same issue their findings collide -- which is exactly what the
        cross-tool agreement matrix in Step 7 depends on.
        """
        basis = "|".join([
            str(self.cwe_id or self.name.lower().strip()),
            self._normalize_url(self.url),
            (self.param or "").lower(),
            (self.method or "").upper(),
        ])
        return hashlib.sha256(basis.encode()).hexdigest()[:16]


    # CWEs describing site-wide configuration rather than a specific
    # endpoint. For these the URL is incidental: two tools reporting a
    # missing header at different paths have found the same issue.
    SITEWIDE_CWES: ClassVar[set[int]] = {
        16, 200, 264, 319, 530, 548, 614, 693, 942, 1004, 1021, 1104, 1188, 1395
    }

    @property
    def class_fingerprint(self) -> str:
        """Location-insensitive fingerprint for site-wide issues.

        Falls back to the full fingerprint for endpoint-specific
        vulnerabilities, where the location *is* the vulnerability.
        """
        if self.cwe_id and self.cwe_id in self.SITEWIDE_CWES:
            return hashlib.sha256(f"sitewide|{self.cwe_id}".encode()).hexdigest()[:16]
        return self.fingerprint


    # CWEs describing site-wide configuration rather than a specific
    # endpoint. For these the URL is incidental: two tools reporting a
    # missing header at different paths have found the same issue.
class ScanResult(BaseModel):
    """Everything produced by one tool against one target."""

    tool: str
    tool_version: str | None = None
    target: str
    base_url: str
    started_at: datetime
    finished_at: datetime
    exit_code: int = 0
    error: str | None = None
    findings: list[Finding] = Field(default_factory=list)
    raw_output_path: str | None = None

    @property
    def duration_seconds(self) -> float:
        return (self.finished_at - self.started_at).total_seconds()

    @property
    def succeeded(self) -> bool:
        return self.error is None
