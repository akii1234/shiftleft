import json
from pathlib import Path
from unittest.mock import patch, MagicMock
from shiftleft.scanners.trivy import TrivyScanner
from shiftleft.models import Severity
from shiftleft.config import ScannerConfig

SAMPLE_TRIVY_OUTPUT = {
    "Results": [
        {
            "Target": "package-lock.json",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-1234",
                    "PkgName": "lodash",
                    "Severity": "HIGH",
                    "Title": "Prototype Pollution in lodash",
                    "CweIDs": ["CWE-1321"]
                }
            ]
        }
    ]
}

def _config(**overrides):
    defaults = dict(enabled=True, tier=1, rules=[], severity_threshold="warning", scan_type="fs")
    defaults.update(overrides)
    return ScannerConfig(**defaults)

def test_trivy_name():
    assert TrivyScanner().name == "trivy"

def test_trivy_parse_output():
    s = TrivyScanner()
    findings = s._parse_output(json.dumps(SAMPLE_TRIVY_OUTPUT))
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].rule_id == "CVE-2023-1234"
    assert findings[0].message == "Prototype Pollution in lodash"
    assert findings[0].cwe == "CWE-1321"

def test_trivy_scan_no_vulns(tmp_path):
    s = TrivyScanner()
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = json.dumps({"Results": []})
    with patch("shiftleft.scanners.trivy.subprocess.run", return_value=mock_result):
        result = s.scan([tmp_path / "package.json"], _config())
    assert result.success is True
    assert result.findings == []

def test_trivy_handles_no_vulnerabilities_key():
    """Some Trivy results have no Vulnerabilities key."""
    s = TrivyScanner()
    output = json.dumps({"Results": [{"Target": "go.sum"}]})
    findings = s._parse_output(output)
    assert findings == []
