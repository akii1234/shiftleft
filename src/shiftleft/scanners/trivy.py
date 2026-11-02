import json
import shutil
import subprocess
import time
from pathlib import Path

from shiftleft.models import Finding, ScanResult, Severity
from shiftleft.config import ScannerConfig
from shiftleft.scanners.base import BaseScanner


class TrivyScanner(BaseScanner):
    """Trivy SCA (Software Composition Analysis) scanner adapter."""

    name = "trivy"
    supported_languages = set()  # SCA — scans lockfiles, not source

    def is_installed(self) -> bool:
        """Check if trivy is installed and available."""
        return shutil.which("trivy") is not None

    def scan(self, files: list[Path], config: ScannerConfig) -> ScanResult:
        """
        Run trivy scan on the given files.

        Args:
            files: List of file paths to scan
            config: Scanner-specific configuration

        Returns:
            ScanResult with findings and metadata
        """
        start_time = time.time()

        try:
            # Determine the repo root from the files list
            if not files:
                return ScanResult(
                    scanner=self.name,
                    findings=[],
                    duration_seconds=0,
                    success=True,
                    error=None,
                )

            # Find common parent directory
            repo_path = Path.cwd()
            if len(files) > 0:
                # Start with the first file's parent
                common_path = files[0].parent
                # Find the deepest common parent
                for file in files[1:]:
                    # Find the common ancestor
                    try:
                        common_path = Path(*[p for p in common_path.parts
                                            if p in file.parts][:len(common_path.parts)])
                    except Exception:
                        common_path = Path.cwd()
                        break
                repo_path = common_path if common_path.is_dir() else Path.cwd()

            # Build command: trivy fs --format json --scanners vuln <repo_path>
            cmd = [
                "trivy",
                "fs",
                "--format",
                "json",
                "--scanners",
                "vuln",
                str(repo_path),
            ]

            # Run trivy
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
                    error=f"Failed to parse trivy output: {e}",
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
                error="Trivy scan timed out",
            )
        except Exception as e:
            duration = time.time() - start_time
            return ScanResult(
                scanner=self.name,
                findings=[],
                duration_seconds=duration,
                success=False,
                error=f"Trivy scan failed: {e}",
            )

    def _parse_output(self, output: str) -> list[Finding]:
        """
        Parse trivy JSON output and extract findings.

        Args:
            output: JSON string from trivy

        Returns:
            List of Finding objects
        """
        data = json.loads(output)
        findings = []

        # Trivy output has a Results array
        for result in data.get("Results", []):
            target = result.get("Target", "")
            vulnerabilities = result.get("Vulnerabilities", [])

            # Handle missing Vulnerabilities key gracefully
            if not vulnerabilities:
                continue

            for vuln in vulnerabilities:
                # Map trivy severity strings directly
                severity_map = {
                    "CRITICAL": Severity.CRITICAL,
                    "HIGH": Severity.HIGH,
                    "MEDIUM": Severity.MEDIUM,
                    "LOW": Severity.LOW,
                    "INFO": Severity.INFO,
                }

                severity_str = vuln.get("Severity", "LOW")
                severity = severity_map.get(severity_str, Severity.LOW)

                # Extract CWE from CweIDs list (first entry if available)
                cwe = None
                cwe_list = vuln.get("CweIDs", [])
                if cwe_list:
                    cwe = cwe_list[0]

                finding = Finding(
                    rule_id=vuln.get("VulnerabilityID", ""),
                    file=target,
                    line=0,  # dependencies don't have line numbers
                    severity=severity,
                    message=vuln.get("Title", ""),
                    scanner=self.name,
                    cwe=cwe,
                )

                findings.append(finding)

        return findings
