"""Cross-tool correlation and deduplication.

Findings from different scanners are collapsed by fingerprint --
a hash of CWE, normalized URL, parameter and method that deliberately
excludes the tool name. Two scanners reporting the same underlying
vulnerability therefore produce the same fingerprint and merge into
a single correlated finding recording which tools agreed.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from src.schema import Finding, ScanResult, Severity


@dataclass
class CorrelatedFinding:
    """One unique vulnerability, with the set of tools that reported it."""

    fingerprint: str
    finding: Finding                       # highest-severity representative
    tools: set[str] = field(default_factory=set)
    instances: int = 0

    @property
    def agreement(self) -> int:
        return len(self.tools)

    @property
    def corroborated(self) -> bool:
        """Reported independently by more than one tool."""
        return len(self.tools) > 1


@dataclass
class Correlation:
    """Result of correlating a set of scan results."""

    target: str
    results: list[ScanResult]
    unique: dict[str, CorrelatedFinding] = field(default_factory=dict)

    # ---- headline numbers -------------------------------------------
    @property
    def raw_count(self) -> int:
        return sum(len(r.findings) for r in self.results)

    @property
    def unique_count(self) -> int:
        return len(self.unique)

    @property
    def dedup_ratio(self) -> float:
        return (1 - self.unique_count / self.raw_count) * 100 if self.raw_count else 0.0

    @property
    def corroborated_count(self) -> int:
        return sum(1 for c in self.unique.values() if c.corroborated)

    # ---- breakdowns --------------------------------------------------
    def by_tool(self) -> dict[str, dict]:
        out = {}
        for r in self.results:
            fps = {f.class_fingerprint for f in r.findings}
            exclusive = {
                fp for fp in fps
                if self.unique.get(fp) and self.unique[fp].tools == {r.tool}
            }
            out[r.tool] = {
                "version": r.tool_version,
                "raw": len(r.findings),
                "unique": len(fps),
                "exclusive": len(exclusive),
                "duration": round(r.duration_seconds, 1),
                "error": r.error,
            }
        return out

    def agreement_matrix(self) -> dict[tuple[str, str], int]:
        """How many unique findings each pair of tools both reported."""
        tools = sorted({r.tool for r in self.results})
        matrix: dict[tuple[str, str], int] = {}
        for a in tools:
            for b in tools:
                matrix[(a, b)] = sum(
                    1 for c in self.unique.values()
                    if a in c.tools and b in c.tools
                )
        return matrix

    def by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = defaultdict(int)
        for c in self.unique.values():
            counts[c.finding.severity.value] += 1
        return dict(counts)

    def by_owasp(self) -> dict[str, int]:
        counts: dict[str, int] = defaultdict(int)
        for c in self.unique.values():
            counts[c.finding.owasp_category or "unmapped"] += 1
        return dict(counts)

    def owasp_coverage_by_tool(self) -> dict[str, set[str]]:
        """Which OWASP categories each tool detected at least once."""
        cov: dict[str, set[str]] = defaultdict(set)
        for r in self.results:
            for f in r.findings:
                if f.owasp_category:
                    cov[r.tool].add(f.owasp_category)
        return dict(cov)

    def top_findings(self, n: int = 25) -> list[CorrelatedFinding]:
        return sorted(
            self.unique.values(),
            key=lambda c: (
                -c.finding.severity.rank,
                -c.agreement,
                -c.instances,
            ),
        )[:n]


def correlate(results: list[ScanResult], target: str) -> Correlation:
    """Collapse findings across tools by fingerprint."""
    corr = Correlation(target=target, results=results)

    for r in results:
        for f in r.findings:
            fp = f.class_fingerprint
            existing = corr.unique.get(fp)
            if existing is None:
                corr.unique[fp] = CorrelatedFinding(
                    fingerprint=fp, finding=f, tools={r.tool}, instances=1
                )
            else:
                existing.tools.add(r.tool)
                existing.instances += 1
                # Keep the highest-severity version as representative
                if f.severity.rank > existing.finding.severity.rank:
                    existing.finding = f

    return corr


def load_results(run_dir: Path) -> list[ScanResult]:
    """Load a run directory's results.json back into ScanResult objects."""
    path = run_dir / "results.json"
    if not path.exists():
        return []
    return [ScanResult(**item) for item in json.loads(path.read_text())]


def load_all(results_root: Path, target: str | None = None) -> list[ScanResult]:
    """Load every scan result, optionally filtered to one target.

    Where a tool has been run against the same target more than once,
    only the most recent run is kept -- otherwise re-runs would be
    counted as corroborating evidence for themselves.
    """
    latest: dict[tuple[str, str], ScanResult] = {}
    for run_dir in sorted(results_root.glob("*/")):
        for r in load_results(run_dir):
            if target and r.target != target:
                continue
            key = (r.tool, r.target)
            if key not in latest or r.started_at > latest[key].started_at:
                latest[key] = r
    return list(latest.values())
