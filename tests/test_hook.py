"""Tests for hook installation and config creation."""

from pathlib import Path
import pytest
from shiftleft.hook import install_hook, create_default_config


def test_install_hook_creates_file(tmp_path):
    """Test that install_hook creates the hook file with proper content."""
    git_dir = tmp_path / ".git" / "hooks"
    git_dir.mkdir(parents=True)
    hook_path = install_hook(tmp_path)
    assert hook_path.exists()
    assert "shiftleft scan" in hook_path.read_text()
    assert hook_path.stat().st_mode & 0o111  # is executable


def test_install_hook_no_git_dir(tmp_path):
    """Should raise FileNotFoundError if not a git repo."""
    with pytest.raises(FileNotFoundError):
        install_hook(tmp_path)


def test_create_default_config(tmp_path):
    """Test that create_default_config creates a config file with all scanners."""
    config_path = create_default_config(tmp_path)
    assert config_path.exists()
    assert config_path.name == ".shiftleft.yml"
    content = config_path.read_text()
    assert "semgrep" in content
    assert "gitleaks" in content
