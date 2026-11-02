import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import yaml

from shiftleft.models import Severity


logger = logging.getLogger(__name__)


@dataclass
class ScannerConfig:
    """Configuration for a single scanner."""
    enabled: bool
    tier: int
    rules: list[str] = field(default_factory=list)
    severity_threshold: str = "info"
    scan_type: Optional[str] = None


@dataclass
class PolicyConfig:
    """Security policy configuration."""
    block_on: list[Severity] = field(default_factory=list)
    warn_on: list[Severity] = field(default_factory=list)
    ignore: list[Severity] = field(default_factory=list)
    emergency_override: bool = True


@dataclass
class ShiftLeftConfig:
    """Complete ShiftLeft configuration."""
    scanners: dict[str, ScannerConfig]
    policy: PolicyConfig


# Default configuration with all Tier 1 scanners enabled
DEFAULT_CONFIG = ShiftLeftConfig(
    scanners={
        "semgrep": ScannerConfig(enabled=True, tier=1),
        "gitleaks": ScannerConfig(enabled=True, tier=1),
        "bandit": ScannerConfig(enabled=True, tier=1),
        "trivy": ScannerConfig(enabled=True, tier=1),
    },
    policy=PolicyConfig(
        block_on=[Severity.CRITICAL, Severity.HIGH],
        warn_on=[Severity.MEDIUM],
        ignore=[],
        emergency_override=True,
    ),
)


def _string_to_severity(s: str) -> Severity:
    """Convert a string (case-insensitive) to a Severity enum."""
    try:
        return Severity[s.upper()]
    except KeyError:
        logger.warning(f"Unknown severity level: {s}, defaulting to INFO")
        return Severity.INFO


def _merge_scanner_config(default: ScannerConfig, override: dict) -> ScannerConfig:
    """Merge override dict into default ScannerConfig."""
    return ScannerConfig(
        enabled=override.get("enabled", default.enabled),
        tier=override.get("tier", default.tier),
        rules=override.get("rules", default.rules),
        severity_threshold=override.get("severity_threshold", default.severity_threshold),
        scan_type=override.get("scan_type", default.scan_type),
    )


def load_config(path: Optional[Path] = None) -> ShiftLeftConfig:
    """
    Load ShiftLeft configuration from a YAML file.

    Searches for config in this order:
    1. Given path (if provided)
    2. Current working directory (.shiftleft.yml)
    3. Global config (~/.shiftleft/config.yml)

    If no file is found or parsing fails, returns DEFAULT_CONFIG.

    Args:
        path: Explicit path to config file, or None to search default locations

    Returns:
        ShiftLeftConfig with merged defaults and file overrides
    """

    config_paths = []

    if path:
        config_paths.append(path)
    else:
        # Search in order: current working directory, then home directory
        config_paths.append(Path.cwd() / ".shiftleft.yml")
        config_paths.append(Path.home() / ".shiftleft" / "config.yml")

    # Try to find and load the config file
    config_file = None
    for candidate in config_paths:
        if candidate.exists() and candidate.is_file():
            config_file = candidate
            break

    # If no file found, return defaults
    if not config_file:
        return DEFAULT_CONFIG

    # Try to parse the YAML file
    try:
        with open(config_file, 'r') as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        logger.warning(f"Failed to parse config file {config_file}: {e}, using defaults")
        return DEFAULT_CONFIG
    except Exception as e:
        logger.warning(f"Error reading config file {config_file}: {e}, using defaults")
        return DEFAULT_CONFIG

    # If the file is empty, return defaults
    if data is None:
        return DEFAULT_CONFIG

    # Merge scanners
    merged_scanners = {}
    for scanner_name, default_scanner in DEFAULT_CONFIG.scanners.items():
        scanner_override = data.get("scanners", {}).get(scanner_name, {})
        if scanner_override:
            merged_scanners[scanner_name] = _merge_scanner_config(default_scanner, scanner_override)
        else:
            merged_scanners[scanner_name] = default_scanner

    # Merge policy
    policy_data = data.get("policy", {})

    # Parse block_on list
    block_on = []
    if "block_on" in policy_data:
        block_on = [_string_to_severity(s) for s in policy_data["block_on"]]
    else:
        block_on = DEFAULT_CONFIG.policy.block_on

    # Parse warn_on list
    warn_on = []
    if "warn_on" in policy_data:
        warn_on = [_string_to_severity(s) for s in policy_data["warn_on"]]
    else:
        warn_on = DEFAULT_CONFIG.policy.warn_on

    # Parse ignore list
    ignore = []
    if "ignore" in policy_data:
        ignore = [_string_to_severity(s) for s in policy_data["ignore"]]
    else:
        ignore = DEFAULT_CONFIG.policy.ignore

    # Parse emergency_override
    emergency_override = policy_data.get("emergency_override", DEFAULT_CONFIG.policy.emergency_override)

    merged_policy = PolicyConfig(
        block_on=block_on,
        warn_on=warn_on,
        ignore=ignore,
        emergency_override=emergency_override,
    )

    return ShiftLeftConfig(scanners=merged_scanners, policy=merged_policy)
