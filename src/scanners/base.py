"""Abstract scanner interface.

Every tool implements this. Adding a new scanner means writing one
subclass -- the CLI, correlation engine and reporting layer need no
changes, because they only ever see ScanResult objects.
"""

from __future__ import annotations

import subprocess
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path

from src.config import Target
from src.schema import Finding, ScanResult

RESULTS_DIR = Path("/app/results")


class Scanner(ABC):
    """Base class for all scanners."""

    name: str = "unnamed"
    default_timeout: int = 900   # seconds

    def __init__(self, run_dir: Path | None = None, timeout: int | None = None):
        self.run_dir = run_dir or RESULTS_DIR
        self.timeout = timeout or self.default_timeout
        self.run_dir.mkdir(parents=True, exist_ok=True)

    # ---- subclasses implement these two -----------------------------
    @abstractmethod
    def _execute(self, target: Target) -> tuple[int, Path]:
        """Run the tool. Return (exit_code, path_to_raw_output)."""

    @abstractmethod
    def _parse(self, raw_path: Path, target: Target) -> list[Finding]:
        """Convert the tool's native output into Finding objects."""

    # ---- optional override ------------------------------------------
    def version(self) -> str | None:
        return None

    # ---- shared plumbing --------------------------------------------
    def scan(self, target: Target) -> ScanResult:
        """Template method: run, parse, wrap. Never raises."""
        started = datetime.now(timezone.utc)
        exit_code, raw_path, error, findings = 0, None, None, []

        try:
            exit_code, raw_path = self._execute(target)
            findings = self._parse(raw_path, target)
        except subprocess.TimeoutExpired:
            error = f"{self.name} exceeded timeout of {self.timeout}s"
            exit_code = -1
        except Exception as exc:                      # noqa: BLE001
            error = f"{type(exc).__name__}: {exc}"
            exit_code = -1

        finished = datetime.now(timezone.utc)
        version = self.version()

        for f in findings:
            f.tool = self.name
            f.tool_version = version
            f.target = target.name

        return ScanResult(
            tool=self.name,
            tool_version=version,
            target=target.name,
            base_url=target.base_url,
            started_at=started,
            finished_at=finished,
            exit_code=exit_code,
            error=error,
            findings=findings,
            raw_output_path=str(raw_path) if raw_path else None,
        )

    # ---- helper for subprocess-based tools ---------------------------
    def _run(self, cmd: list[str]) -> subprocess.CompletedProcess:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=self.timeout,
            check=False,
        )
