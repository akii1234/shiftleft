import json
import os
import shutil
import subprocess
import time
from pathlib import Path

from shiftleft.models import Finding, ScanResult, Severity
from shiftleft.config import ScannerConfig
from shiftleft.scanners.base import BaseScanner


class GitleaksScanner(BaseScanner):
    """Gitleaks secret detection scanner adapter."""

    name = "gitleaks"
    supported_languages = set()  # scans all languages — secrets can be anywhere

    def is_installed(self) -> bool:
        """Check if gitleaks is installed and available."""
        return shutil.which("gitleaks") is not None

    def scan(self, files: list[Path], config: ScannerConfig) -> ScanResult:
        """
        Run gitleaks scan on the given files.

        Args:
            files: List of file paths to scan
            config: Scanner-specific configuration

        Returns:
            ScanResult with findings and metadata
        """
        start_time = time.time()

        try:
            # Determine the repo root from the files list
            # Use the common parent directory of all files
            if not files:
                return ScanResult(
                    scanner=self.name,
                    findings=[],
                    duration_seconds=0,
                    success=True,
                    error=None,
                )

            # Find common parent directory
            try:
                common = Path(os.path.commonpath([str(f) for f in files]))
                repo_path = common if common.is_dir() else common.parent
            except ValueError:
                repo_path = Path.cwd()

            # Build command: gitleaks detect --source <repo_path> --report-format json --report-path /dev/stdout --no-git
            cmd = [
                "gitleaks",
                "detect",
                "--source",
                str(repo_path),
                "--report-format",
                "json",
                "--report-path",
                "/dev/stdout",
                "--no-git",
            ]

            # Run gitleaks
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            duration = time.time() - start_time

            # Parse output
            try:
                findings = self._parse_output(result.stdout)
            except (json.JSONDecodeError, KeyError, TypeError) as e:
                return ScanResult(
                    scanner=self.name,
                    findings=[],
                    duration_seconds=duration,
                    success=False,
                    error=f"Failed to parse gitleaks output: {e}",
                )

            return ScanResult(
                scanner=self.name,
                findings=findings,
                duration_seconds=duration,
                success=True,
                error=None,
            )

        except subprocess.TimeoutExpired:
            duration = time.time() - start_time
            return ScanResult(
                scanner=self.name,
                findings=[],
                duration_seconds=duration,
                success=False,
                error="Gitleaks scan timed out",
            )
        except Exception as e:
            duration = time.time() - start_time
            return ScanResult(
                scanner=self.name,
                findings=[],
                duration_seconds=duration,
                success=False,
                error=f"Gitleaks scan failed: {e}",
            )

    def _parse_output(self, output: str) -> list[Finding]:
        """
        Parse gitleaks JSON output and extract findings.

        Args:
            output: JSON string from gitleaks (array format)

        Returns:
            List of Finding objects
        """
        data = json.loads(output)
        findings = []

        # Gitleaks output is a JSON array of findings
        if isinstance(data, list):
            for item in data:
                finding = Finding(
                    rule_id=item.get("RuleID", ""),
                    file=item.get("File", ""),
                    line=item.get("StartLine", 0),
                    severity=Severity.CRITICAL,  # all secrets are critical
                    message=item.get("Description", ""),
                    scanner=self.name,
                    cwe=None,
                )
                findings.append(finding)

        return findings
