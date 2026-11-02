from shiftleft.models import Severity, Finding, ScanResult

def test_severity_ordering():
    assert Severity.CRITICAL.value > Severity.HIGH.value > Severity.MEDIUM.value > Severity.LOW.value > Severity.INFO.value

def test_finding_creation():
    f = Finding(rule_id="secret-detected", file="src/config.ts", line=42, severity=Severity.CRITICAL, message="AWS key", scanner="gitleaks", cwe="CWE-798")
    assert f.scanner == "gitleaks"
    assert f.cwe == "CWE-798"

def test_finding_cwe_optional():
    f = Finding(rule_id="test", file="a.py", line=1, severity=Severity.LOW, message="test", scanner="semgrep", cwe=None)
    assert f.cwe is None

def test_scan_result_no_findings():
    r = ScanResult(scanner="semgrep", findings=[], duration_seconds=0.5, success=True, error=None)
    assert r.success is True
    assert len(r.findings) == 0

def test_scan_result_with_error():
    r = ScanResult(scanner="bandit", findings=[], duration_seconds=0.0, success=False, error="bandit not found")
    assert r.success is False
    assert "not found" in r.error
