import json
from pathlib import Path
from unittest.mock import patch, MagicMock
from shiftleft.scanners.gitleaks import GitleaksScanner
from shiftleft.models import Severity
from shiftleft.config import ScannerConfig

SAMPLE_GITLEAKS_OUTPUT = [
    {
        "RuleID": "aws-access-key-id",
        "File": "src/config.ts",
        "StartLine": 42,
        "Description": "AWS Access Key ID",
        "Tags": ["key", "AWS"]
    }
]

def _config(**overrides):
    defaults = dict(enabled=True, tier=1, rules=[], severity_threshold="warning", scan_type=None)
    defaults.update(overrides)
    return ScannerConfig(**defaults)

def test_gitleaks_name():
    assert GitleaksScanner().name == "gitleaks"

def test_gitleaks_parse_output():
    s = GitleaksScanner()
    findings = s._parse_output(json.dumps(SAMPLE_GITLEAKS_OUTPUT))
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL  # all secrets are critical
    assert findings[0].file == "src/config.ts"
    assert findings[0].rule_id == "aws-access-key-id"

def test_gitleaks_scan_no_findings(tmp_path):
    s = GitleaksScanner()
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "[]"
    with patch("shiftleft.scanners.gitleaks.subprocess.run", return_value=mock_result):
        result = s.scan([tmp_path / "app.py"], _config())
    assert result.success is True
    assert result.findings == []

def test_gitleaks_all_findings_are_critical():
    """Secrets should always be CRITICAL severity."""
    s = GitleaksScanner()
    findings = s._parse_output(json.dumps(SAMPLE_GITLEAKS_OUTPUT))
    for f in findings:
        assert f.severity == Severity.CRITICAL
