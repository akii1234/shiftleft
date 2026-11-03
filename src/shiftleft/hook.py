"""Pre-push hook installation and default configuration creation."""

from pathlib import Path
import yaml

from shiftleft.config import DEFAULT_CONFIG


_HOOK_SCRIPT = """\
#!/bin/sh
# ShiftLeft Gateway pre-push hook
shiftleft scan
exit $?
"""


def install_hook(repo_path: Path, global_install: bool = False) -> Path:
    """
    Install the pre-push hook to a repository.

    Args:
        repo_path: Path to the repository root
        global_install: If True, install globally (not implemented yet)

    Returns:
        Path to the installed hook

    Raises:
        FileNotFoundError: If .git directory doesn't exist
    """
    repo_path = Path(repo_path)
    git_dir = repo_path / ".git" / "hooks"

    # Check if .git/hooks exists
    if not git_dir.exists():
        raise FileNotFoundError(f"Git hooks directory not found: {git_dir}")

    # Write hook script to destination
    hook_dest = git_dir / "pre-push"
    hook_dest.write_text(_HOOK_SCRIPT)

    # Make executable
    hook_dest.chmod(hook_dest.stat().st_mode | 0o111)

    return hook_dest


def create_default_config(repo_path: Path) -> Path:
    """
    Create a default .shiftleft.yml configuration file.

    Args:
        repo_path: Path to the repository root

    Returns:
        Path to the created configuration file
    """
    repo_path = Path(repo_path)
    config_path = repo_path / ".shiftleft.yml"

    # Convert DEFAULT_CONFIG to YAML-serializable format
    config_dict = {
        "scanners": {
            name: {
                "enabled": scanner.enabled,
                "tier": scanner.tier,
                "rules": scanner.rules,
                "severity_threshold": scanner.severity_threshold,
            }
            for name, scanner in DEFAULT_CONFIG.scanners.items()
        },
        "policy": {
            "block_on": [s.name.lower() for s in DEFAULT_CONFIG.policy.block_on],
            "warn_on": [s.name.lower() for s in DEFAULT_CONFIG.policy.warn_on],
            "ignore": [s.name.lower() for s in DEFAULT_CONFIG.policy.ignore],
            "emergency_override": DEFAULT_CONFIG.policy.emergency_override,
        },
    }

    # Write to file
    with open(config_path, "w") as f:
        yaml.dump(config_dict, f, default_flow_style=False, sort_keys=False)

    return config_path
