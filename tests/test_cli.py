from typer.testing import CliRunner
from unittest.mock import patch, MagicMock
from shiftleft.cli import app
from shiftleft.models import ScanResult, Finding, Severity
from shiftleft.orchestrator import OrchestratorResult

runner = CliRunner()

def _clean_result():
    return OrchestratorResult(results=[], total_findings=[], duration_seconds=0.5)

def _blocked_result():
    f = Finding(rule_id="R1", file="a.py", line=1, severity=Severity.CRITICAL, message="bad", scanner="test", cwe=None)
    return OrchestratorResult(
        results=[ScanResult(scanner="test", findings=[f], duration_seconds=0.1, success=True, error=None)],
        total_findings=[f],
        duration_seconds=0.5,
    )

@patch("shiftleft.cli.run_scans")
@patch("shiftleft.cli.get_changed_files", return_value=[])
def test_scan_no_files(mock_git, mock_scans):
    result = runner.invoke(app, ["scan"])
    assert result.exit_code == 0
    assert "No files to scan" in result.output

@patch("shiftleft.cli.run_scans", return_value=_clean_result())
@patch("shiftleft.cli.get_changed_files", return_value=["a.py"])
def test_scan_clean(mock_git, mock_scans):
    result = runner.invoke(app, ["scan"])
    assert result.exit_code == 0

@patch("shiftleft.cli.run_scans", return_value=_blocked_result())
@patch("shiftleft.cli.get_changed_files", return_value=["a.py"])
def test_scan_blocked_exit_code_1(mock_git, mock_scans):
    result = runner.invoke(app, ["scan"])
    assert result.exit_code == 1
