import yaml
from pathlib import Path
from shiftleft.config import load_config, ShiftLeftConfig, DEFAULT_CONFIG
from shiftleft.models import Severity


def test_load_defaults_when_no_file(tmp_path):
    config = load_config(tmp_path / "nonexistent.yml")
    assert config.scanners["semgrep"].enabled is True
    assert config.scanners["bandit"].enabled is True
    assert config.scanners["gitleaks"].enabled is True
    assert config.scanners["trivy"].enabled is True


def test_load_from_yaml(tmp_path):
    cfg_file = tmp_path / ".shiftleft.yml"
    cfg_file.write_text(yaml.dump({
        "scanners": {"semgrep": {"enabled": False}, "bandit": {"enabled": True}},
        "policy": {"block_on": ["critical"], "warn_on": ["high", "medium"]}
    }))
    config = load_config(cfg_file)
    assert config.scanners["semgrep"].enabled is False
    assert config.scanners["bandit"].enabled is True


def test_policy_defaults():
    config = load_config(None)
    assert "CRITICAL" in [s.name for s in config.policy.block_on]
    assert config.policy.emergency_override is True


def test_malformed_yaml_returns_defaults(tmp_path):
    cfg_file = tmp_path / ".shiftleft.yml"
    cfg_file.write_text(": invalid: yaml: [")
    config = load_config(cfg_file)
    assert config.scanners["semgrep"].enabled is True  # fell back to defaults
