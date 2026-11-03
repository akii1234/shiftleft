import json
import shutil
import subprocess
import time
from pathlib import Path

from shiftleft.models import Finding, ScanResult, Severity
from shiftleft.config import ScannerConfig
from shiftleft.scanners.base import BaseScanner


class BanditScanner(BaseScanner):
    """Bandit security scanner adapter for Python code."""

    name = "bandit"
    supported_languages = {"python"}

    def is_installed(self) -> bool:
        """Check if bandit is installed and available."""
        return shutil.which("bandit") is not None

    def filter_files(self, files: list[Path]) -> list[Path]:
        """
        Filter files to only include Python files (.py).

        Args:
            files: List of file paths

        Returns:
            Filtered list of Python file paths
        """
        return [f for f in files if f.suffix == ".py"]

    def scan(self, files: list[Path], config: ScannerConfig) -> ScanResult:
        """
        Run bandit scan on the given files.

        Args:
            files: List of file paths to scan
            config: Scanner-specific configuration

        Returns:
            ScanResult with findings and metadata
        """
        start_time = time.time()

        # If no Python files, return success immediately
        if not files:
            return ScanResult(
                scanner=self.name,
                findings=[],
                duration_seconds=0.0,
                success=True,
                error=None,
            )

        try:
            # Build command: bandit -f json -r <files>
            cmd = ["bandit", "-f", "json", "-r"]
            cmd.extend(str(f) for f in files)

            # Run bandit
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            duration = time.time() - start_time

            # Parse output
            try:
                findings = self._parse_output(result.stdout)
            except (json.JSONDecodeError, KeyError) as e:
                return ScanResult(
                    scanner=self.name,
                    findings=[],
                    duration_seconds=duration,
                    success=False,
                    error=f"Failed to parse bandit output: {e}",
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
                error="Bandit scan timed out",
            )
        except Exception as e:
            duration = time.time() - start_time
            return ScanResult(
                scanner=self.name,
                findings=[],
                duration_seconds=duration,
                success=False,
                error=f"Bandit scan failed: {e}",
            )

    def _parse_output(self, output: str) -> list[Finding]:
        """
        Parse bandit JSON output and extract findings.

        Args:
            output: JSON string from bandit

        Returns:
            List of Finding objects
        """
        data = json.loads(output)
        findings = []

        for result in data.get("results", []):
            # Map severity strings directly
            severity_map = {
                "LOW": Severity.LOW,
                "MEDIUM": Severity.MEDIUM,
                "HIGH": Severity.HIGH,
            }

            issue_severity = result.get("issue_severity", "LOW")
            severity = severity_map.get(issue_severity, Severity.LOW)

            # Extract CWE from issue_cwe
            cwe = None
            issue_cwe = result.get("issue_cwe")
            if issue_cwe and isinstance(issue_cwe, dict):
                cwe_id = issue_cwe.get("id")
                if cwe_id is not None:
                    cwe = f"CWE-{cwe_id}"

            finding = Finding(
                rule_id=result.get("test_id", ""),
                file=result.get("filename", ""),
                line=result.get("line_number", 0),
                severity=severity,
                message=result.get("issue_text", ""),
                scanner=self.name,
                cwe=cwe,
            )

            findings.append(finding)

        return findings
