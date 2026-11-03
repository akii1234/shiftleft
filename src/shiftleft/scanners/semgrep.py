import json
import shutil
import subprocess
import time
from pathlib import Path

from shiftleft.models import Finding, ScanResult, Severity
from shiftleft.config import ScannerConfig
from shiftleft.scanners.base import BaseScanner


class SemgrepScanner(BaseScanner):
    """Semgrep security scanner adapter."""

    name = "semgrep"
    supported_languages = {"python", "javascript", "typescript", "java", "go", "ruby"}

    def is_installed(self) -> bool:
        """Check if semgrep is installed and available."""
        return shutil.which("semgrep") is not None

    def scan(self, files: list[Path], config: ScannerConfig) -> ScanResult:
        """
        Run semgrep scan on the given files.

        Args:
            files: List of file paths to scan
            config: Scanner-specific configuration

        Returns:
            ScanResult with findings and metadata
        """
        start_time = time.time()

        try:
            # Build command: semgrep scan --json --config <rules> <files>
            cmd = ["semgrep", "scan", "--json"]

            # Add rules from config
            if config.rules:
                for rule in config.rules:
                    cmd.extend(["--config", rule])

            # Add files
            cmd.extend(str(f) for f in files)

            # Run semgrep
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            duration = time.time() - start_time

            try:
                findings = self._parse_output(result.stdout)
            except (json.JSONDecodeError, KeyError) as e:
                return ScanResult(
                    scanner=self.name,
                    findings=[],
                    duration_seconds=duration,
                    success=False,
                    error=f"Failed to parse semgrep output: {e}",
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
                error="Semgrep scan timed out",
            )
        except Exception as e:
            duration = time.time() - start_time
            return ScanResult(
                scanner=self.name,
                findings=[],
                duration_seconds=duration,
                success=False,
                error=f"Semgrep scan failed: {e}",
            )

    def _parse_output(self, output: str) -> list[Finding]:
        """
        Parse semgrep JSON output and extract findings.

        Args:
            output: JSON string from semgrep

        Returns:
            List of Finding objects
        """
        data = json.loads(output)
        findings = []

        for result in data.get("results", []):
            # Map semgrep severity to our Severity enum
            severity_map = {
                "ERROR": Severity.HIGH,
                "WARNING": Severity.MEDIUM,
                "INFO": Severity.LOW,
            }

            semgrep_severity = result.get("extra", {}).get("severity", "INFO")
            severity = severity_map.get(semgrep_severity, Severity.LOW)

            # Extract CWE from metadata (first entry if available)
            cwe = None
            cwe_list = result.get("extra", {}).get("metadata", {}).get("cwe", [])
            if cwe_list:
                cwe = cwe_list[0]

            finding = Finding(
                rule_id=result.get("check_id", ""),
                file=result.get("path", ""),
                line=result.get("start", {}).get("line", 0),
                severity=severity,
                message=result.get("extra", {}).get("message", ""),
                scanner=self.name,
                cwe=cwe,
            )

            findings.append(finding)

        return findings
