"""Scanner orchestrator for parallel execution of security scanners."""
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

from shiftleft.config import ShiftLeftConfig
from shiftleft.models import Finding, ScanResult
from shiftleft.scanners.registry import ScannerRegistry


@dataclass
class OrchestratorResult:
    """Result of orchestrated scanner execution."""
    results: list[ScanResult]
    total_findings: list[Finding]
    duration_seconds: float


def run_scans(
    files: list[Path],
    config: ShiftLeftConfig,
    registry: ScannerRegistry,
    tier: int = 1,
) -> OrchestratorResult:
    """
    Run all enabled scanners for the given tier in parallel.

    Args:
        files: List of file paths to scan
        config: ShiftLeft configuration
        registry: Scanner registry containing registered scanners
        tier: Scanner tier to run (default: 1)

    Returns:
        OrchestratorResult with aggregated findings and metadata
    """
    start_time = time.time()

    # Get all registered scanners and filter those that should run
    scanners = []
    for scanner in registry._scanners.values():
        # Check if scanner is installed
        if not scanner.is_installed():
            continue

        # Check if scanner is in config and matches tier
        if scanner.name in config.scanners:
            scanner_config = config.scanners[scanner.name]
            if scanner_config.tier == tier and scanner_config.enabled:
                scanners.append(scanner)
        else:
            # Scanner not in config - run it anyway if installed
            scanners.append(scanner)

    results: list[ScanResult] = []
    total_findings: list[Finding] = []

    if not scanners:
        # No scanners to run
        duration = time.time() - start_time
        return OrchestratorResult(
            results=results,
            total_findings=total_findings,
            duration_seconds=duration,
        )

    # Get scanner-specific config
    def run_scanner(scanner):
        """Run a single scanner with error handling."""
        try:
            # Filter files according to scanner's requirements
            filtered_files = scanner.filter_files(files)

            # Get the scanner's config
            scanner_config = config.scanners.get(scanner.name)

            # Run the scanner
            result = scanner.scan(filtered_files, scanner_config)
            return result
        except Exception as e:
            # Wrap exception in failed ScanResult
            return ScanResult(
                scanner=scanner.name,
                findings=[],
                duration_seconds=0.0,
                success=False,
                error=str(e),
            )

    # Execute scanners in parallel using ThreadPoolExecutor
    with ThreadPoolExecutor() as executor:
        # Submit all scanner tasks
        future_to_scanner = {
            executor.submit(run_scanner, scanner): scanner
            for scanner in scanners
        }

        # Collect results as they complete
        for future in as_completed(future_to_scanner):
            result = future.result()
            results.append(result)

            # Aggregate findings from successful scans
            if result.success:
                total_findings.extend(result.findings)

    duration = time.time() - start_time

    return OrchestratorResult(
        results=results,
        total_findings=total_findings,
        duration_seconds=duration,
    )
