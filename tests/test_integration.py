"""Integration tests for the full ShiftLeft Gateway scan pipeline."""

import json
from pathlib import Path
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner

from shiftleft.cli import app

runner = CliRunner()

# Clean output formats for each scanner
SEMGREP_CLEAN = json.dumps({"results": []})
GITLEAKS_CLEAN = "[]"
BANDIT_CLEAN = json.dumps({"results": []})
TRIVY_CLEAN = json.dumps({"Results": []})


def _mock_subprocess_run(*args, **kwargs):
    """Mock all scanner subprocesses to return clean results."""
    cmd = args[0] if args else kwargs.get("args", [])
    result = MagicMock()
    result.returncode = 0

    cmd_str = str(cmd).lower()
    if "semgrep" in cmd_str:
        result.stdout = SEMGREP_CLEAN
    elif "gitleaks" in cmd_str:
        result.stdout = GITLEAKS_CLEAN
    elif "bandit" in cmd_str:
        result.stdout = BANDIT_CLEAN
    elif "trivy" in cmd_str:
        result.stdout = TRIVY_CLEAN
    else:
        result.stdout = ""

    return result


@patch("shiftleft.scanners.semgrep.subprocess.run", side_effect=_mock_subprocess_run)
@patch("shiftleft.scanners.gitleaks.subprocess.run", side_effect=_mock_subprocess_run)
@patch("shiftleft.scanners.bandit.subprocess.run", side_effect=_mock_subprocess_run)
@patch("shiftleft.scanners.trivy.subprocess.run", side_effect=_mock_subprocess_run)
@patch("shiftleft.scanners.semgrep.shutil.which", return_value="/usr/bin/semgrep")
@patch("shiftleft.scanners.gitleaks.shutil.which", return_value="/usr/bin/gitleaks")
@patch("shiftleft.scanners.bandit.shutil.which", return_value="/usr/bin/bandit")
@patch("shiftleft.scanners.trivy.shutil.which", return_value="/usr/bin/trivy")
@patch("shiftleft.cli.get_changed_files", return_value=[Path("src/app.py"), Path("src/utils.js")])
def test_full_clean_scan(*mocks):
    """Test that a full clean scan with all scanners installed returns exit code 0."""
    result = runner.invoke(app, ["scan"])
    assert result.exit_code == 0


@patch("shiftleft.scanners.semgrep.shutil.which", return_value=None)
@patch("shiftleft.scanners.gitleaks.shutil.which", return_value=None)
@patch("shiftleft.scanners.bandit.shutil.which", return_value=None)
@patch("shiftleft.scanners.trivy.shutil.which", return_value=None)
@patch("shiftleft.cli.get_changed_files", return_value=[Path("src/app.py")])
def test_scan_with_no_scanners_installed(*mocks):
    """Should pass with exit code 0 even when no scanners are installed (no findings = no block)."""
    result = runner.invoke(app, ["scan"])
    assert result.exit_code == 0
