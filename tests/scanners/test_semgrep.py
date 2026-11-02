import json
from pathlib import Path
from unittest.mock import patch, MagicMock
from shiftleft.scanners.semgrep import SemgrepScanner
from shiftleft.models import Severity
from shiftleft.config import ScannerConfig

SAMPLE_SEMGREP_OUTPUT = {
    "results": [
        {
            "check_id": "python.lang.security.audit.exec-detected",
            "path": "src/app.py",
            "start": {"line": 10},
            "extra": {
                "severity": "ERROR",
                "message": "Detected exec() call",
                "metadata": {"cwe": ["CWE-78"]}
            }
        }
    ]
}

def _config(**overrides):
    defaults = dict(enabled=True, tier=1, rules=["p/owasp-top-ten"], severity_threshold="warning", scan_type=None)
    defaults.update(overrides)
    return ScannerConfig(**defaults)

def test_semgrep_name():
    s = SemgrepScanner()
    assert s.name == "semgrep"

def test_semgrep_parse_output():
    s = SemgrepScanner()
    findings = s._parse_output(json.dumps(SAMPLE_SEMGREP_OUTPUT))
    assert len(findings) == 1
    assert findings[0].rule_id == "python.lang.security.audit.exec-detected"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].cwe == "CWE-78"

def test_semgrep_scan_success(tmp_path):
    s = SemgrepScanner()
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = json.dumps({"results": []})
    with patch("shiftleft.scanners.semgrep.subprocess.run", return_value=mock_result):
        result = s.scan([tmp_path / "app.py"], _config())
    assert result.success is True
    assert result.findings == []

def test_semgrep_not_installed():
    s = SemgrepScanner()
    with patch("shiftleft.scanners.semgrep.shutil.which", return_value=None):
        assert s.is_installed() is False
