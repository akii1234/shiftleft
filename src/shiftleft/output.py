"""Terminal output formatter using Rich library."""

from rich.console import Console
from rich.table import Table
from rich.text import Text

from shiftleft.config import PolicyConfig
from shiftleft.models import Finding, Severity
from shiftleft.orchestrator import OrchestratorResult


def should_block(findings: list[Finding], policy: PolicyConfig) -> bool:
    """
    Determine if the findings should block execution based on policy.

    Args:
        findings: List of security findings
        policy: Security policy configuration

    Returns:
        True if any finding's severity is in policy.block_on, False otherwise
    """
    if not findings:
        return False

    for finding in findings:
        if finding.severity in policy.block_on:
            return True

    return False


def _severity_color(severity: Severity) -> str:
    """Map severity level to Rich color."""
    color_map = {
        Severity.CRITICAL: "red",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.INFO: "cyan",
    }
    return color_map.get(severity, "white")


def format_results(result: OrchestratorResult, policy: PolicyConfig) -> None:
    """
    Format and print orchestrator results to terminal using Rich.

    Prints:
    1. Scanner results table (name, duration, finding count)
    2. Each finding with colored severity, file:line, message
    3. PASS/BLOCKED banner at the end

    Args:
        result: OrchestratorResult from orchestrator
        policy: Security policy configuration
    """
    console = Console()

    # Print scanner results table
    console.print("\n[bold]Scanner Results[/bold]")
    scanner_table = Table(show_header=True, header_style="bold")
    scanner_table.add_column("Scanner", style="cyan")
    scanner_table.add_column("Duration (s)", justify="right")
    scanner_table.add_column("Findings", justify="right")
    scanner_table.add_column("Status")

    for scan_result in result.results:
        status = "[green]✓[/green]" if scan_result.success else "[red]✗[/red]"
        finding_count = len(scan_result.findings)
        scanner_table.add_row(
            scan_result.scanner,
            f"{scan_result.duration_seconds:.2f}",
            str(finding_count),
            status,
        )

    console.print(scanner_table)

    # Print findings
    if result.total_findings:
        console.print("\n[bold]Findings[/bold]")
        findings_table = Table(show_header=True, header_style="bold")
        findings_table.add_column("Severity")
        findings_table.add_column("Location")
        findings_table.add_column("Message")
        findings_table.add_column("Scanner")
        findings_table.add_column("Rule ID")

        for finding in result.total_findings:
            severity_color = _severity_color(finding.severity)
            severity_text = Text(finding.severity.name, style=severity_color)
            location = f"{finding.file}:{finding.line}"

            findings_table.add_row(
                severity_text,
                location,
                finding.message,
                finding.scanner,
                finding.rule_id,
            )

        console.print(findings_table)
    else:
        console.print("\n[green]No findings detected[/green]")

    # Print PASS/BLOCKED banner
    console.print()
    if should_block(result.total_findings, policy):
        console.print("[red bold]BLOCKED[/red bold] - Findings exceed policy thresholds")
    else:
        console.print("[green bold]PASS[/green bold] - All findings within policy thresholds")
    console.print()
