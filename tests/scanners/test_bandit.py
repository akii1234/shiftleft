import json
from pathlib import Path
from unittest.mock import patch, MagicMock
from shiftleft.scanners.bandit import BanditScanner
from shiftleft.models import Severity
from shiftleft.config import ScannerConfig

SAMPLE_BANDIT_OUTPUT = {
    "results": [
        {
            "test_id": "B102",
            "filename": "src/app.py",
            "line_number": 15,
            "issue_severity": "HIGH",
            "issue_confidence": "HIGH",
            "issue_text": "Use of exec detected.",
            "issue_cwe": {"id": 78}
        }
    ]
}

def _config(**overrides):
    defaults = dict(enabled=True, tier=1, rules=[], severity_threshold="warning", scan_type=None)
    defaults.update(overrides)
    return ScannerConfig(**defaults)

def test_bandit_name():
    assert BanditScanner().name == "bandit"

def test_bandit_filter_files_only_python():
    s = BanditScanner()
    files = [Path("a.py"), Path("b.js"), Path("c.py"), Path("d.ts")]
    filtered = s.filter_files(files)
    assert filtered == [Path("a.py"), Path("c.py")]

def test_bandit_parse_output():
    s = BanditScanner()
    findings = s._parse_output(json.dumps(SAMPLE_BANDIT_OUTPUT))
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].cwe == "CWE-78"
    assert findings[0].rule_id == "B102"

def test_bandit_scan_skips_if_no_python_files(tmp_path):
    s = BanditScanner()
    result = s.scan([tmp_path / "app.js"], _config())
    assert result.success is True
    assert result.findings == []
    assert result.duration_seconds == 0.0
