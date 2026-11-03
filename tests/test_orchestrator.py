import asyncio
from pathlib import Path
from unittest.mock import MagicMock
from shiftleft.orchestrator import run_scans, OrchestratorResult
from shiftleft.models import Finding, ScanResult, Severity
from shiftleft.scanners.base import BaseScanner
from shiftleft.scanners.registry import ScannerRegistry
from shiftleft.config import load_config


def _make_scanner(name, findings=None):
    class S(BaseScanner):
        supported_languages = set()
        def is_installed(self): return True
        def scan(self, files, config):
            return ScanResult(scanner=name, findings=findings or [], duration_seconds=0.1, success=True, error=None)
    s = S()
    s.__class__.name = name
    return s


def _finding(scanner="test", severity=Severity.HIGH):
    return Finding(rule_id="R1", file="a.py", line=1, severity=severity, message="test", scanner=scanner, cwe=None)


def test_run_scans_empty_registry():
    reg = ScannerRegistry()
    config = load_config(None)
    result = run_scans([], config, reg)
    assert result.total_findings == []
    assert result.results == []


def test_run_scans_aggregates_findings():
    reg = ScannerRegistry()
    reg.register(_make_scanner("s1", [_finding("s1")]))
    reg.register(_make_scanner("s2", [_finding("s2"), _finding("s2")]))
    config = load_config(None)
    result = run_scans([Path("a.py")], config, reg)
    assert len(result.total_findings) == 3
    assert len(result.results) == 2


def test_run_scans_handles_scanner_failure():
    class FailScanner(BaseScanner):
        name = "fail"
        supported_languages = set()
        def is_installed(self): return True
        def scan(self, files, config): raise RuntimeError("boom")
    reg = ScannerRegistry()
    reg.register(FailScanner())
    config = load_config(None)
    result = run_scans([Path("a.py")], config, reg)
    assert len(result.results) == 1
    assert result.results[0].success is False
    assert "boom" in result.results[0].error
