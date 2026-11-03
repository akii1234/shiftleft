from shiftleft.output import should_block
from shiftleft.models import Finding, Severity
from shiftleft.config import load_config


def _finding(severity):
    return Finding(rule_id="R1", file="a.py", line=1, severity=severity, message="test", scanner="test", cwe=None)


def test_should_block_on_critical():
    policy = load_config(None).policy
    assert should_block([_finding(Severity.CRITICAL)], policy) is True


def test_should_block_on_high():
    policy = load_config(None).policy
    assert should_block([_finding(Severity.HIGH)], policy) is True


def test_should_not_block_on_medium():
    policy = load_config(None).policy
    assert should_block([_finding(Severity.MEDIUM)], policy) is False


def test_should_not_block_empty():
    policy = load_config(None).policy
    assert should_block([], policy) is False
