"""CLI entry point for ShiftLeft Gateway."""

import subprocess
import sys
from pathlib import Path
from typing import Optional

import typer

from shiftleft.config import load_config
from shiftleft.git import get_changed_files
from shiftleft.orchestrator import run_scans
from shiftleft.output import format_results, should_block
from shiftleft.scanners.registry import ScannerRegistry
from shiftleft.scanners.semgrep import SemgrepScanner
from shiftleft.scanners.gitleaks import GitleaksScanner
from shiftleft.scanners.bandit import BanditScanner
from shiftleft.scanners.trivy import TrivyScanner

app = typer.Typer(help="ShiftLeft Gateway — shift security scans left to the developer.")


def _build_registry() -> ScannerRegistry:
    """Build a scanner registry with all four Tier 1 scanners registered."""
    registry = ScannerRegistry()
    registry.register(SemgrepScanner())
    registry.register(GitleaksScanner())
    registry.register(BanditScanner())
    registry.register(TrivyScanner())
    return registry


@app.command()
def init(
    global_: bool = typer.Option(False, "--global", help="Install globally"),
) -> None:
    """Create config file and install pre-push hook. (Task 12)"""
    typer.echo("init: not yet implemented")
    raise typer.Exit(code=0)


@app.command()
def scan(
    config: Optional[Path] = typer.Option(None, "--config", help="Path to config file"),
    all_files: bool = typer.Option(False, "--all-files", help="Scan all tracked files instead of changed files"),
) -> None:
    """Scan files for security issues."""
    # Load config
    cfg = load_config(config)

    # Determine files to scan
    if all_files:
        result = subprocess.run(["git", "ls-files"], capture_output=True, text=True)
        if result.returncode != 0 or not result.stdout.strip():
            files = []
        else:
            files = [Path(line.strip()) for line in result.stdout.strip().split("\n") if line.strip()]
    else:
        files = get_changed_files()

    if not files:
        typer.echo("No files to scan")
        raise typer.Exit(code=0)

    # Build registry and run scans
    registry = _build_registry()
    orchestrator_result = run_scans(files, cfg, registry, tier=1)

    # Format and print results
    format_results(orchestrator_result, cfg.policy)

    # Exit with code 1 if blocked
    if should_block(orchestrator_result.total_findings, cfg.policy):
        raise typer.Exit(code=1)
