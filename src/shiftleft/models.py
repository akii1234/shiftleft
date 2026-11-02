from dataclasses import dataclass
from enum import IntEnum


class Severity(IntEnum):
    """Security finding severity levels with numeric ordering."""
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


@dataclass
class Finding:
    """A single security finding from a scanner."""
    rule_id: str
    file: str
    line: int
    severity: Severity
    message: str
    scanner: str
    cwe: str | None


@dataclass
class ScanResult:
    """Result of running a single scanner."""
    scanner: str
    findings: list[Finding]
    duration_seconds: float
    success: bool
    error: str | None
