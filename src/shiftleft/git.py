"""Git operations for changed file detection and language identification."""

import subprocess
from pathlib import Path


# Mapping of file extensions to programming language identifiers
EXTENSION_TO_LANGUAGE = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".tf": "terraform",
}


def get_changed_files(repo_path: Path | None = None) -> list[Path]:
    """
    Get list of files changed between HEAD and the remote tracking branch.
    Falls back to staged+unstaged changes if no remote tracking branch exists.

    Args:
        repo_path: Path to the git repository (defaults to current directory)

    Returns:
        List of Path objects for changed files
    """
    if repo_path is None:
        repo_path = Path.cwd()
    else:
        repo_path = Path(repo_path)

    # Try to get diff against upstream branch first
    result = subprocess.run(
        ["git", "diff", "--name-only", "HEAD", "@{upstream}"],
        cwd=repo_path,
        capture_output=True,
        text=True,
    )

    # If upstream doesn't exist, fall back to unstaged+staged changes
    if result.returncode != 0:
        result = subprocess.run(
            ["git", "diff", "--name-only", "HEAD"],
            cwd=repo_path,
            capture_output=True,
            text=True,
        )

    if result.returncode != 0 or not result.stdout.strip():
        return []

    # Parse output - return relative paths from git diff
    files = []
    for line in result.stdout.strip().split("\n"):
        if line.strip():
            files.append(Path(line.strip()))

    return files


def detect_languages(files: list[Path]) -> set[str]:
    """
    Detect programming languages from file extensions.

    Args:
        files: List of Path objects

    Returns:
        Set of language identifiers (e.g., {"python", "javascript"})
    """
    languages = set()

    for file_path in files:
        suffix = file_path.suffix.lower()
        if suffix in EXTENSION_TO_LANGUAGE:
            languages.add(EXTENSION_TO_LANGUAGE[suffix])

    return languages
