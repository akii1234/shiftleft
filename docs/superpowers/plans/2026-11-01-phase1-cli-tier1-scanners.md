# Phase 1: CLI + Pre-Push Hook with Tier 1 Scanners — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the ShiftLeft Gateway CLI that runs Semgrep, Gitleaks, Bandit, and Trivy on changed files, displays results in the terminal, and blocks `git push` via a pre-push hook when findings exceed the configured severity threshold.

**Architecture:** A Python CLI (Typer) with a pluggable scanner registry. Each scanner is a thin adapter that wraps the scanner's CLI, normalizes output to a common Finding dataclass, and reports pass/fail. A Scanner Orchestrator runs enabled scanners in parallel via asyncio. A git pre-push hook shell script invokes the CLI on changed files. Configuration lives in `.shiftleft.yml` (YAML).

**Tech Stack:** Python 3.11+, Typer (CLI), PyYAML (config), asyncio (parallel scans), subprocess (scanner invocation), pytest (tests)

**Spec:** `docs/design.md` (ShiftLeft Gateway Design Document v3)

## Global Constraints

- Python 3.11+ required
- No external Python dependencies beyond: `typer`, `pyyaml`, `rich` (terminal output)
- Scanners are invoked as subprocesses — Semgrep, Gitleaks, Bandit, Trivy must be installed on the machine
- CLI entry point: `shiftleft` (via `pyproject.toml` console_scripts)
- Config file: `.shiftleft.yml` (repo-local) or `~/.shiftleft/config.yml` (global)
- All scanner output normalized to SARIF-compatible Finding dataclass before display
- Pre-push hook must complete Tier 1 scan in under 10 seconds for typical changesets
- No AI/LLM functionality in Phase 1 — this is pure deterministic scanning

## Review Focus

1. **Scanner not installed:** User runs `shiftleft scan` but Semgrep is not installed — should print clear "Semgrep not found, install with: pip install semgrep" and skip that scanner (not crash).
2. **Empty changeset:** `git push` with no changed files — should pass immediately with "No files to scan" message, not invoke any scanners.
3. **Scanner timeout:** Semgrep hangs on a huge file — should timeout after configured limit and report the timeout as a warning, not block indefinitely.
4. **Malformed config:** `.shiftleft.yml` has invalid YAML or unknown scanner name — should print a clear error and fall back to defaults, not traceback.
5. **Mixed language changeset:** Push contains `.py`, `.js`, and `.tf` files — Bandit should only receive `.py` files, Semgrep should get all, and the orchestrator should not send unsupported files to language-specific scanners.

---

## File Structure

```
shiftleft-gateway/
├── pyproject.toml                          # Package config, dependencies, console_scripts
├── src/
│   └── shiftleft/
│       ├── __init__.py
│       ├── cli.py                          # Typer CLI entry point (scan, init, install)
│       ├── config.py                       # YAML config loader + defaults
│       ├── models.py                       # Finding, Severity, ScanResult dataclasses
│       ├── git.py                          # Git diff: get changed files
│       ├── orchestrator.py                 # Scanner orchestrator (parallel execution)
│       ├── output.py                       # Terminal output formatter (Rich)
│       ├── hook.py                         # Pre-push hook installer
│       └── scanners/
│           ├── __init__.py
│           ├── base.py                     # BaseScanner ABC
│           ├── registry.py                 # Scanner registry (discover + instantiate)
│           ├── semgrep.py                  # Semgrep adapter
│           ├── gitleaks.py                 # Gitleaks adapter
│           ├── bandit.py                   # Bandit adapter
│           └── trivy.py                    # Trivy adapter
├── hooks/
│   └── pre-push                            # Shell script installed by `shiftleft init`
└── tests/
    ├── conftest.py                         # Shared fixtures
    ├── test_config.py
    ├── test_models.py
    ├── test_git.py
    ├── test_orchestrator.py
    ├── test_output.py
    ├── test_hook.py
    ├── test_cli.py
    └── scanners/
        ├── test_base.py
        ├── test_registry.py
        ├── test_semgrep.py
        ├── test_gitleaks.py
        ├── test_bandit.py
        └── test_trivy.py
```

---

### Task 1: Project Scaffolding + Models

**Files:**
- Create: `pyproject.toml`
- Create: `src/shiftleft/__init__.py`
- Create: `src/shiftleft/models.py`
- Test: `tests/test_models.py`
- Create: `tests/conftest.py`

**Interfaces:**
- Consumes: nothing (first task)
- Produces:
  - `Severity` enum: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`
  - `Finding(rule_id: str, file: str, line: int, severity: Severity, message: str, scanner: str, cwe: str | None)`
  - `ScanResult(scanner: str, findings: list[Finding], duration_seconds: float, success: bool, error: str | None)`

- [ ] **Step 1: Create `pyproject.toml`**

```toml
[project]
name = "shiftleft-gateway"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = [
    "typer>=0.9.0",
    "pyyaml>=6.0",
    "rich>=13.0",
]

[project.scripts]
shiftleft = "shiftleft.cli:app"

[build-system]
requires = ["setuptools>=68.0"]
build-backend = "setuptools.backends._legacy:_Backend"

[tool.setuptools.packages.find]
where = ["src"]

[tool.pytest.ini_options]
testpaths = ["tests"]
```

- [ ] **Step 2: Create `src/shiftleft/__init__.py`**

Empty file with `__version__ = "0.1.0"`.

- [ ] **Step 3: Write failing tests for models**

```python
# tests/test_models.py
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
```

- [ ] **Step 4: Run tests — verify they fail**

Run: `cd /Users/akhiltripathi/dev/shiftleft-gateway && python -m pytest tests/test_models.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'shiftleft'`

- [ ] **Step 5: Implement `models.py`**

`Severity` as `IntEnum` (INFO=1, LOW=2, MEDIUM=3, HIGH=4, CRITICAL=5). `Finding` and `ScanResult` as `dataclasses.dataclass`.

- [ ] **Step 6: Create empty `tests/conftest.py`**

Empty file for now, will hold shared fixtures in later tasks.

- [ ] **Step 7: Run tests — verify they pass**

Run: `cd /Users/akhiltripathi/dev/shiftleft-gateway && pip install -e ".[dev]" && python -m pytest tests/test_models.py -v`
Expected: All 5 tests PASS

- [ ] **Step 8: Commit**

```bash
git init
git add pyproject.toml src/shiftleft/__init__.py src/shiftleft/models.py tests/conftest.py tests/test_models.py
git commit -m "feat: project scaffolding with Finding and ScanResult models"
```

---

### Task 2: Configuration Loader

**Files:**
- Create: `src/shiftleft/config.py`
- Test: `tests/test_config.py`

**Interfaces:**
- Consumes: `Severity` from `models.py`
- Produces:
  - `ScannerConfig(enabled: bool, tier: int, rules: list[str], severity_threshold: str, scan_type: str | None)`
  - `PolicyConfig(block_on: list[Severity], warn_on: list[Severity], ignore: list[Severity], emergency_override: bool)`
  - `ShiftLeftConfig(scanners: dict[str, ScannerConfig], policy: PolicyConfig)`
  - `load_config(path: Path | None = None) -> ShiftLeftConfig` — loads `.shiftleft.yml` from given path, cwd, or global `~/.shiftleft/config.yml`; returns defaults if none found

- [ ] **Step 1: Write failing tests for config**

```python
# tests/test_config.py
import yaml
from pathlib import Path
from shiftleft.config import load_config, ShiftLeftConfig, DEFAULT_CONFIG

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
```

- [ ] **Step 2: Run tests — verify they fail**

Run: `python -m pytest tests/test_config.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement `config.py`**

Define `DEFAULT_CONFIG` dict matching the design doc defaults. `load_config` reads YAML, merges over defaults. Wraps parse errors in a warning log and returns defaults. Use `dataclasses` for `ScannerConfig`, `PolicyConfig`, `ShiftLeftConfig`.

- [ ] **Step 4: Run tests — verify they pass**

Run: `python -m pytest tests/test_config.py -v`
Expected: All 4 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/shiftleft/config.py tests/test_config.py
git commit -m "feat: YAML config loader with defaults and fallback"
```

---

### Task 3: Git Changed Files Detection

**Files:**
- Create: `src/shiftleft/git.py`
- Test: `tests/test_git.py`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `get_changed_files(repo_path: Path | None = None) -> list[Path]` — returns list of files changed between HEAD and the remote tracking branch (for pre-push), or staged+unstaged changes if no remote
  - `detect_languages(files: list[Path]) -> set[str]` — returns set of language identifiers from file extensions (e.g. `{"python", "javascript", "typescript"}`)

- [ ] **Step 1: Write failing tests**

```python
# tests/test_git.py
from pathlib import Path
from shiftleft.git import detect_languages, get_changed_files
from unittest.mock import patch

def test_detect_languages_python():
    files = [Path("src/app.py"), Path("src/utils.py")]
    langs = detect_languages(files)
    assert "python" in langs

def test_detect_languages_mixed():
    files = [Path("a.py"), Path("b.js"), Path("c.ts"), Path("d.java")]
    langs = detect_languages(files)
    assert langs == {"python", "javascript", "typescript", "java"}

def test_detect_languages_empty():
    assert detect_languages([]) == set()

def test_get_changed_files_uses_git_diff(tmp_path):
    mock_output = "src/app.py\nsrc/utils.js\n"
    with patch("shiftleft.git.subprocess.run") as mock_run:
        mock_run.return_value.stdout = mock_output
        mock_run.return_value.returncode = 0
        files = get_changed_files(tmp_path)
    assert Path("src/app.py") in files
    assert Path("src/utils.js") in files

def test_get_changed_files_empty_diff(tmp_path):
    with patch("shiftleft.git.subprocess.run") as mock_run:
        mock_run.return_value.stdout = ""
        mock_run.return_value.returncode = 0
        files = get_changed_files(tmp_path)
    assert files == []
```

- [ ] **Step 2: Run tests — verify they fail**

Run: `python -m pytest tests/test_git.py -v`
Expected: FAIL

- [ ] **Step 3: Implement `git.py`**

`get_changed_files`: runs `git diff --name-only HEAD @{upstream}` via `subprocess.run`, falls back to `git diff --name-only HEAD` if no upstream. Filters to only files that exist on disk. `detect_languages`: maps extensions (`.py` -> `python`, `.js` -> `javascript`, `.ts/.tsx` -> `typescript`, `.java` -> `java`, `.go` -> `go`, `.tf` -> `terraform`).

- [ ] **Step 4: Run tests — verify they pass**

Run: `python -m pytest tests/test_git.py -v`
Expected: All 5 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/shiftleft/git.py tests/test_git.py
git commit -m "feat: git changed file detection and language detection"
```

---

### Task 4: Base Scanner + Scanner Registry

**Files:**
- Create: `src/shiftleft/scanners/__init__.py`
- Create: `src/shiftleft/scanners/base.py`
- Create: `src/shiftleft/scanners/registry.py`
- Test: `tests/scanners/test_base.py`
- Test: `tests/scanners/test_registry.py`

**Interfaces:**
- Consumes: `Finding`, `ScanResult`, `Severity` from `models.py`; `ScannerConfig` from `config.py`
- Produces:
  - `BaseScanner` ABC with methods:
    - `name: str` (property)
    - `supported_languages: set[str]` (property)
    - `is_installed() -> bool`
    - `scan(files: list[Path], config: ScannerConfig) -> ScanResult`
    - `filter_files(files: list[Path]) -> list[Path]` — default: return all; language-specific scanners override
  - `ScannerRegistry` class:
    - `register(scanner: BaseScanner) -> None`
    - `get_enabled(config: ShiftLeftConfig) -> list[BaseScanner]`
    - `get_for_tier(tier: int, config: ShiftLeftConfig) -> list[BaseScanner]`

- [ ] **Step 1: Write failing tests**

```python
# tests/scanners/test_base.py
import pytest
from pathlib import Path
from shiftleft.scanners.base import BaseScanner
from shiftleft.models import ScanResult

def test_base_scanner_is_abstract():
    with pytest.raises(TypeError):
        BaseScanner()

def test_filter_files_default_returns_all():
    class DummyScanner(BaseScanner):
        name = "dummy"
        supported_languages = {"python"}
        def is_installed(self): return True
        def scan(self, files, config): return ScanResult(scanner=self.name, findings=[], duration_seconds=0, success=True, error=None)
    s = DummyScanner()
    files = [Path("a.py"), Path("b.js")]
    assert s.filter_files(files) == files
```

```python
# tests/scanners/test_registry.py
from shiftleft.scanners.registry import ScannerRegistry
from shiftleft.scanners.base import BaseScanner
from shiftleft.models import ScanResult
from shiftleft.config import load_config

def _make_scanner(name, installed=True):
    class S(BaseScanner):
        supported_languages = {"python"}
        def is_installed(self): return installed
        def scan(self, files, config): return ScanResult(scanner=self.name, findings=[], duration_seconds=0, success=True, error=None)
    s = S()
    s.__class__.name = name  # override class-level
    return s

def test_register_and_get_enabled():
    reg = ScannerRegistry()
    reg.register(_make_scanner("semgrep"))
    reg.register(_make_scanner("bandit"))
    config = load_config(None)
    enabled = reg.get_enabled(config)
    names = [s.name for s in enabled]
    assert "semgrep" in names
    assert "bandit" in names

def test_get_enabled_skips_uninstalled():
    reg = ScannerRegistry()
    reg.register(_make_scanner("semgrep", installed=False))
    config = load_config(None)
    enabled = reg.get_enabled(config)
    assert len(enabled) == 0
```

- [ ] **Step 2: Run tests — verify they fail**

Run: `python -m pytest tests/scanners/ -v`
Expected: FAIL

- [ ] **Step 3: Implement `base.py` and `registry.py`**

`BaseScanner`: ABC with `@abstractmethod` for `scan` and `is_installed`. `name` and `supported_languages` as class-level attributes. `filter_files` as default method returning all files. `ScannerRegistry`: stores scanners in a dict by name, `get_enabled` checks both config `enabled` flag and `is_installed()`.

- [ ] **Step 4: Run tests — verify they pass**

Run: `python -m pytest tests/scanners/ -v`
Expected: All 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/shiftleft/scanners/__init__.py src/shiftleft/scanners/base.py src/shiftleft/scanners/registry.py tests/scanners/test_base.py tests/scanners/test_registry.py
git commit -m "feat: BaseScanner ABC and ScannerRegistry"
```

---

### Task 5: Semgrep Scanner Adapter

**Files:**
- Create: `src/shiftleft/scanners/semgrep.py`
- Test: `tests/scanners/test_semgrep.py`

**Interfaces:**
- Consumes: `BaseScanner` from `base.py`; `Finding`, `ScanResult`, `Severity` from `models.py`; `ScannerConfig` from `config.py`
- Produces: `SemgrepScanner(BaseScanner)` — `name = "semgrep"`, `supported_languages = {"python", "javascript", "typescript", "java", "go", "ruby"}`

- [ ] **Step 1: Write failing tests**

```python
# tests/scanners/test_semgrep.py
import json
from pathlib import Path
from unittest.mock import patch, MagicMock
from shiftleft.scanners.semgrep import SemgrepScanner
from shiftleft.models import Severity
from shiftleft.config import ScannerConfig

SAMPLE_SEMGREP_OUTPUT = {
    "results": [
        {
            "check_id": "python.lang.security.audit.exec-detected",
            "path": "src/app.py",
            "start": {"line": 10},
            "extra": {
                "severity": "ERROR",
                "message": "Detected exec() call",
                "metadata": {"cwe": ["CWE-78"]}
            }
        }
    ]
}

def _config(**overrides):
    defaults = dict(enabled=True, tier=1, rules=["p/owasp-top-ten"], severity_threshold="warning", scan_type=None)
    defaults.update(overrides)
    return ScannerConfig(**defaults)

def test_semgrep_name():
    s = SemgrepScanner()
    assert s.name == "semgrep"

def test_semgrep_parse_output():
    s = SemgrepScanner()
    findings = s._parse_output(json.dumps(SAMPLE_SEMGREP_OUTPUT))
    assert len(findings) == 1
    assert findings[0].rule_id == "python.lang.security.audit.exec-detected"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].cwe == "CWE-78"

def test_semgrep_scan_success(tmp_path):
    s = SemgrepScanner()
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = json.dumps({"results": []})
    with patch("shiftleft.scanners.semgrep.subprocess.run", return_value=mock_result):
        result = s.scan([tmp_path / "app.py"], _config())
    assert result.success is True
    assert result.findings == []

def test_semgrep_not_installed():
    s = SemgrepScanner()
    with patch("shiftleft.scanners.semgrep.shutil.which", return_value=None):
        assert s.is_installed() is False
```

- [ ] **Step 2: Run tests — verify they fail**

Run: `python -m pytest tests/scanners/test_semgrep.py -v`
Expected: FAIL

- [ ] **Step 3: Implement `semgrep.py`**

Invokes `semgrep scan --json --config <rules> <files>`. Parses JSON output. Maps Semgrep severity (`ERROR` -> `HIGH`, `WARNING` -> `MEDIUM`, `INFO` -> `LOW`). Extracts CWE from `metadata.cwe` list (takes first). `is_installed` checks `shutil.which("semgrep")`. Timeout via `subprocess.run(timeout=...)`.

- [ ] **Step 4: Run tests — verify they pass**

Run: `python -m pytest tests/scanners/test_semgrep.py -v`
Expected: All 4 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/shiftleft/scanners/semgrep.py tests/scanners/test_semgrep.py
git commit -m "feat: Semgrep scanner adapter"
```

---

### Task 6: Gitleaks Scanner Adapter

**Files:**
- Create: `src/shiftleft/scanners/gitleaks.py`
- Test: `tests/scanners/test_gitleaks.py`

**Interfaces:**
- Consumes: `BaseScanner`, `Finding`, `ScanResult`, `Severity`, `ScannerConfig`
- Produces: `GitleaksScanner(BaseScanner)` — `name = "gitleaks"`, `supported_languages = set()` (all languages — secrets can be anywhere)

- [ ] **Step 1: Write failing tests**

```python
# tests/scanners/test_gitleaks.py
import json
from pathlib import Path
from unittest.mock import patch, MagicMock
from shiftleft.scanners.gitleaks import GitleaksScanner
from shiftleft.models import Severity
from shiftleft.config import ScannerConfig

SAMPLE_GITLEAKS_OUTPUT = [
    {
        "RuleID": "aws-access-key-id",
        "File": "src/config.ts",
        "StartLine": 42,
        "Description": "AWS Access Key ID",
        "Tags": ["key", "AWS"]
    }
]

def _config(**overrides):
    defaults = dict(enabled=True, tier=1, rules=[], severity_threshold="warning", scan_type=None)
    defaults.update(overrides)
    return ScannerConfig(**defaults)

def test_gitleaks_name():
    assert GitleaksScanner().name == "gitleaks"

def test_gitleaks_parse_output():
    s = GitleaksScanner()
    findings = s._parse_output(json.dumps(SAMPLE_GITLEAKS_OUTPUT))
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL  # all secrets are critical
    assert findings[0].file == "src/config.ts"
    assert findings[0].rule_id == "aws-access-key-id"

def test_gitleaks_scan_no_findings(tmp_path):
    s = GitleaksScanner()
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "[]"
    with patch("shiftleft.scanners.gitleaks.subprocess.run", return_value=mock_result):
        result = s.scan([tmp_path / "app.py"], _config())
    assert result.success is True
    assert result.findings == []

def test_gitleaks_all_findings_are_critical():
    """Secrets should always be CRITICAL severity."""
    s = GitleaksScanner()
    findings = s._parse_output(json.dumps(SAMPLE_GITLEAKS_OUTPUT))
    for f in findings:
        assert f.severity == Severity.CRITICAL
```

- [ ] **Step 2: Run tests — verify they fail**

Run: `python -m pytest tests/scanners/test_gitleaks.py -v`
Expected: FAIL

- [ ] **Step 3: Implement `gitleaks.py`**

Invokes `gitleaks detect --source <repo_path> --report-format json --report-path /dev/stdout --no-git`. Parses JSON array output. All secret findings are `Severity.CRITICAL`. `is_installed` checks `shutil.which("gitleaks")`. Note: Gitleaks scans the repo path, not individual files — pass the repo root dir.

- [ ] **Step 4: Run tests — verify they pass**

Run: `python -m pytest tests/scanners/test_gitleaks.py -v`
Expected: All 4 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/shiftleft/scanners/gitleaks.py tests/scanners/test_gitleaks.py
git commit -m "feat: Gitleaks scanner adapter"
```

---

### Task 7: Bandit Scanner Adapter

**Files:**
- Create: `src/shiftleft/scanners/bandit.py`
- Test: `tests/scanners/test_bandit.py`

**Interfaces:**
- Consumes: `BaseScanner`, `Finding`, `ScanResult`, `Severity`, `ScannerConfig`
- Produces: `BanditScanner(BaseScanner)` — `name = "bandit"`, `supported_languages = {"python"}`; overrides `filter_files` to return only `.py` files

- [ ] **Step 1: Write failing tests**

```python
# tests/scanners/test_bandit.py
import json
from pathlib import Path
from unittest.mock import patch, MagicMock
from shiftleft.scanners.bandit import BanditScanner
from shiftleft.models import Severity
from shiftleft.config import ScannerConfig

SAMPLE_BANDIT_OUTPUT = {
    "results": [
        {
            "test_id": "B102",
            "filename": "src/app.py",
            "line_number": 15,
            "issue_severity": "HIGH",
            "issue_confidence": "HIGH",
            "issue_text": "Use of exec detected.",
            "issue_cwe": {"id": 78}
        }
    ]
}

def _config(**overrides):
    defaults = dict(enabled=True, tier=1, rules=[], severity_threshold="warning", scan_type=None)
    defaults.update(overrides)
    return ScannerConfig(**defaults)

def test_bandit_name():
    assert BanditScanner().name == "bandit"

def test_bandit_filter_files_only_python():
    s = BanditScanner()
    files = [Path("a.py"), Path("b.js"), Path("c.py"), Path("d.ts")]
    filtered = s.filter_files(files)
    assert filtered == [Path("a.py"), Path("c.py")]

def test_bandit_parse_output():
    s = BanditScanner()
    findings = s._parse_output(json.dumps(SAMPLE_BANDIT_OUTPUT))
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].cwe == "CWE-78"
    assert findings[0].rule_id == "B102"

def test_bandit_scan_skips_if_no_python_files(tmp_path):
    s = BanditScanner()
    result = s.scan([tmp_path / "app.js"], _config())
    assert result.success is True
    assert result.findings == []
    assert result.duration_seconds == 0.0
```

- [ ] **Step 2: Run tests — verify they fail**

Run: `python -m pytest tests/scanners/test_bandit.py -v`
Expected: FAIL

- [ ] **Step 3: Implement `bandit.py`**

Invokes `bandit -f json -r <files>`. Parses JSON output. Maps severity strings directly. Extracts CWE as `CWE-{id}` from `issue_cwe.id`. `filter_files` returns only `.py` files. If no `.py` files, returns success with empty findings immediately (no subprocess). `is_installed` checks `shutil.which("bandit")`.

- [ ] **Step 4: Run tests — verify they pass**

Run: `python -m pytest tests/scanners/test_bandit.py -v`
Expected: All 4 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/shiftleft/scanners/bandit.py tests/scanners/test_bandit.py
git commit -m "feat: Bandit scanner adapter (Python-only)"
```

---

### Task 8: Trivy Scanner Adapter

**Files:**
- Create: `src/shiftleft/scanners/trivy.py`
- Test: `tests/scanners/test_trivy.py`

**Interfaces:**
- Consumes: `BaseScanner`, `Finding`, `ScanResult`, `Severity`, `ScannerConfig`
- Produces: `TrivyScanner(BaseScanner)` — `name = "trivy"`, `supported_languages = set()` (SCA — scans lockfiles, not source)

- [ ] **Step 1: Write failing tests**

```python
# tests/scanners/test_trivy.py
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
```

- [ ] **Step 2: Run tests — verify they fail**

Run: `python -m pytest tests/scanners/test_trivy.py -v`
Expected: FAIL

- [ ] **Step 3: Implement `trivy.py`**

Invokes `trivy fs --format json --scanners vuln <repo_path>`. Parses JSON. Maps severity strings. Extracts CWE from `CweIDs` list (first entry). The `file` field uses the `Target` from Trivy's output (typically the lockfile path). `is_installed` checks `shutil.which("trivy")`.

- [ ] **Step 4: Run tests — verify they pass**

Run: `python -m pytest tests/scanners/test_trivy.py -v`
Expected: All 4 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/shiftleft/scanners/trivy.py tests/scanners/test_trivy.py
git commit -m "feat: Trivy scanner adapter (SCA)"
```

---

### Task 9: Scanner Orchestrator

**Files:**
- Create: `src/shiftleft/orchestrator.py`
- Test: `tests/test_orchestrator.py`

**Interfaces:**
- Consumes: `ScannerRegistry` from `registry.py`; `ShiftLeftConfig` from `config.py`; `ScanResult`, `Finding` from `models.py`
- Produces:
  - `OrchestratorResult(results: list[ScanResult], total_findings: list[Finding], duration_seconds: float)`
  - `run_scans(files: list[Path], config: ShiftLeftConfig, registry: ScannerRegistry, tier: int = 1) -> OrchestratorResult` — runs all enabled scanners for the given tier in parallel, aggregates results

- [ ] **Step 1: Write failing tests**

```python
# tests/test_orchestrator.py
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
```

- [ ] **Step 2: Run tests — verify they fail**

Run: `python -m pytest tests/test_orchestrator.py -v`
Expected: FAIL

- [ ] **Step 3: Implement `orchestrator.py`**

Uses `concurrent.futures.ThreadPoolExecutor` to run scanners in parallel (simpler than asyncio for subprocess-heavy work). Each scanner gets `filter_files` applied first. Catches exceptions per-scanner and wraps in a failed `ScanResult`. Returns `OrchestratorResult` with combined findings and total duration.

- [ ] **Step 4: Run tests — verify they pass**

Run: `python -m pytest tests/test_orchestrator.py -v`
Expected: All 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/shiftleft/orchestrator.py tests/test_orchestrator.py
git commit -m "feat: parallel scanner orchestrator"
```

---

### Task 10: Terminal Output Formatter

**Files:**
- Create: `src/shiftleft/output.py`
- Test: `tests/test_output.py`

**Interfaces:**
- Consumes: `OrchestratorResult` from `orchestrator.py`; `ScanResult`, `Finding`, `Severity` from `models.py`; `PolicyConfig` from `config.py`
- Produces:
  - `format_results(result: OrchestratorResult, policy: PolicyConfig) -> None` — prints formatted output to terminal using Rich
  - `should_block(findings: list[Finding], policy: PolicyConfig) -> bool` — returns True if any finding severity is in `policy.block_on`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_output.py
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
```

- [ ] **Step 2: Run tests — verify they fail**

Run: `python -m pytest tests/test_output.py -v`
Expected: FAIL

- [ ] **Step 3: Implement `output.py`**

`should_block`: checks if any finding's severity is in `policy.block_on`. `format_results`: uses Rich `Console` and `Table` to print scanner results (name, duration, finding count) and then each finding with colored severity, file:line, message. Prints PASS/BLOCKED banner at the end.

- [ ] **Step 4: Run tests — verify they pass**

Run: `python -m pytest tests/test_output.py -v`
Expected: All 4 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/shiftleft/output.py tests/test_output.py
git commit -m "feat: terminal output formatter with Rich"
```

---

### Task 11: CLI Entry Point

**Files:**
- Create: `src/shiftleft/cli.py`
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `load_config` from `config.py`; `get_changed_files` from `git.py`; `run_scans` from `orchestrator.py`; `format_results`, `should_block` from `output.py`; `ScannerRegistry` from `registry.py`; all four scanner classes
- Produces:
  - `app` — Typer application with commands:
    - `shiftleft scan [--config PATH] [--all-files]` — scan changed files (or all with `--all-files`), exit code 1 if blocked
    - `shiftleft init [--global]` — create config file + install hook (Task 12)

- [ ] **Step 1: Write failing tests**

```python
# tests/test_cli.py
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock
from shiftleft.cli import app
from shiftleft.models import ScanResult, Finding, Severity
from shiftleft.orchestrator import OrchestratorResult

runner = CliRunner()

def _clean_result():
    return OrchestratorResult(results=[], total_findings=[], duration_seconds=0.5)

def _blocked_result():
    f = Finding(rule_id="R1", file="a.py", line=1, severity=Severity.CRITICAL, message="bad", scanner="test", cwe=None)
    return OrchestratorResult(
        results=[ScanResult(scanner="test", findings=[f], duration_seconds=0.1, success=True, error=None)],
        total_findings=[f],
        duration_seconds=0.5,
    )

@patch("shiftleft.cli.run_scans")
@patch("shiftleft.cli.get_changed_files", return_value=[])
def test_scan_no_files(mock_git, mock_scans):
    result = runner.invoke(app, ["scan"])
    assert result.exit_code == 0
    assert "No files to scan" in result.output

@patch("shiftleft.cli.run_scans", return_value=_clean_result())
@patch("shiftleft.cli.get_changed_files", return_value=["a.py"])
def test_scan_clean(mock_git, mock_scans):
    result = runner.invoke(app, ["scan"])
    assert result.exit_code == 0

@patch("shiftleft.cli.run_scans", return_value=_blocked_result())
@patch("shiftleft.cli.get_changed_files", return_value=["a.py"])
def test_scan_blocked_exit_code_1(mock_git, mock_scans):
    result = runner.invoke(app, ["scan"])
    assert result.exit_code == 1
```

- [ ] **Step 2: Run tests — verify they fail**

Run: `python -m pytest tests/test_cli.py -v`
Expected: FAIL

- [ ] **Step 3: Implement `cli.py`**

Create Typer `app`. `scan` command: loads config, gets changed files, builds registry with all four scanners registered, calls `run_scans`, calls `format_results`, exits with code 1 if `should_block` returns True. Handles `--config` and `--all-files` options. `--all-files` uses `git ls-files` instead of diff.

- [ ] **Step 4: Run tests — verify they pass**

Run: `python -m pytest tests/test_cli.py -v`
Expected: All 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/shiftleft/cli.py tests/test_cli.py
git commit -m "feat: CLI entry point with scan command"
```

---

### Task 12: Pre-Push Hook Installer

**Files:**
- Create: `src/shiftleft/hook.py`
- Create: `hooks/pre-push`
- Test: `tests/test_hook.py`

**Interfaces:**
- Consumes: nothing external
- Produces:
  - `install_hook(repo_path: Path, global_install: bool = False) -> Path` — writes pre-push hook script, returns path to installed hook
  - `create_default_config(repo_path: Path) -> Path` — writes default `.shiftleft.yml`, returns path
  - Wires into `cli.py` as the `init` command

- [ ] **Step 1: Write failing tests**

```python
# tests/test_hook.py
from pathlib import Path
from shiftleft.hook import install_hook, create_default_config

def test_install_hook_creates_file(tmp_path):
    git_dir = tmp_path / ".git" / "hooks"
    git_dir.mkdir(parents=True)
    hook_path = install_hook(tmp_path)
    assert hook_path.exists()
    assert "shiftleft scan" in hook_path.read_text()
    assert hook_path.stat().st_mode & 0o111  # is executable

def test_install_hook_no_git_dir(tmp_path):
    """Should raise if not a git repo."""
    import pytest
    with pytest.raises(FileNotFoundError):
        install_hook(tmp_path)

def test_create_default_config(tmp_path):
    config_path = create_default_config(tmp_path)
    assert config_path.exists()
    assert config_path.name == ".shiftleft.yml"
    content = config_path.read_text()
    assert "semgrep" in content
    assert "gitleaks" in content
```

- [ ] **Step 2: Run tests — verify they fail**

Run: `python -m pytest tests/test_hook.py -v`
Expected: FAIL

- [ ] **Step 3: Create `hooks/pre-push` template**

```bash
#!/bin/sh
# ShiftLeft Gateway pre-push hook
# Runs Tier 1 security scan on changed files before push

shiftleft scan
exit $?
```

- [ ] **Step 4: Implement `hook.py`**

`install_hook`: copies the pre-push template to `.git/hooks/pre-push` (or global hooks dir if `global_install`), sets executable permission. `create_default_config`: writes a default `.shiftleft.yml` with all Tier 1 scanners enabled.

- [ ] **Step 5: Wire `init` command into `cli.py`**

Add `init` command to the Typer app that calls `create_default_config` and `install_hook`, with `--global` flag.

- [ ] **Step 6: Run tests — verify they pass**

Run: `python -m pytest tests/test_hook.py -v`
Expected: All 3 tests PASS

- [ ] **Step 7: Run full test suite**

Run: `python -m pytest tests/ -v`
Expected: All tests PASS

- [ ] **Step 8: Commit**

```bash
git add src/shiftleft/hook.py hooks/pre-push tests/test_hook.py src/shiftleft/cli.py
git commit -m "feat: pre-push hook installer and init command"
```

---

### Task 13: Integration Test — End-to-End Scan

**Files:**
- Create: `tests/test_integration.py`

**Interfaces:**
- Consumes: all modules (cli, config, git, orchestrator, scanners, output)
- Produces: end-to-end validation that the full pipeline works

- [ ] **Step 1: Write integration tests**

```python
# tests/test_integration.py
from typer.testing import CliRunner
from unittest.mock import patch
from shiftleft.cli import app
from pathlib import Path
import json

runner = CliRunner()

SEMGREP_CLEAN = json.dumps({"results": []})
GITLEAKS_CLEAN = "[]"
BANDIT_CLEAN = json.dumps({"results": []})
TRIVY_CLEAN = json.dumps({"Results": []})

def _mock_subprocess_run(*args, **kwargs):
    """Mock all scanner subprocesses to return clean results."""
    from unittest.mock import MagicMock
    cmd = args[0] if args else kwargs.get("args", [])
    result = MagicMock()
    result.returncode = 0
    if "semgrep" in str(cmd):
        result.stdout = SEMGREP_CLEAN
    elif "gitleaks" in str(cmd):
        result.stdout = GITLEAKS_CLEAN
    elif "bandit" in str(cmd):
        result.stdout = BANDIT_CLEAN
    elif "trivy" in str(cmd):
        result.stdout = TRIVY_CLEAN
    return result

@patch("shiftleft.scanners.semgrep.subprocess.run", side_effect=_mock_subprocess_run)
@patch("shiftleft.scanners.gitleaks.subprocess.run", side_effect=_mock_subprocess_run)
@patch("shiftleft.scanners.bandit.subprocess.run", side_effect=_mock_subprocess_run)
@patch("shiftleft.scanners.trivy.subprocess.run", side_effect=_mock_subprocess_run)
@patch("shiftleft.scanners.semgrep.shutil.which", return_value="/usr/bin/semgrep")
@patch("shiftleft.scanners.gitleaks.shutil.which", return_value="/usr/bin/gitleaks")
@patch("shiftleft.scanners.bandit.shutil.which", return_value="/usr/bin/bandit")
@patch("shiftleft.scanners.trivy.shutil.which", return_value="/usr/bin/trivy")
@patch("shiftleft.cli.get_changed_files", return_value=[Path("src/app.py"), Path("src/utils.js")])
def test_full_clean_scan(*mocks):
    result = runner.invoke(app, ["scan"])
    assert result.exit_code == 0

@patch("shiftleft.scanners.semgrep.shutil.which", return_value=None)
@patch("shiftleft.scanners.gitleaks.shutil.which", return_value=None)
@patch("shiftleft.scanners.bandit.shutil.which", return_value=None)
@patch("shiftleft.scanners.trivy.shutil.which", return_value=None)
@patch("shiftleft.cli.get_changed_files", return_value=[Path("src/app.py")])
def test_scan_with_no_scanners_installed(*mocks):
    """Should still pass (no scanners = no findings), but warn."""
    result = runner.invoke(app, ["scan"])
    assert result.exit_code == 0
```

- [ ] **Step 2: Run integration tests**

Run: `python -m pytest tests/test_integration.py -v`
Expected: All tests PASS

- [ ] **Step 3: Run full test suite**

Run: `python -m pytest tests/ -v --tb=short`
Expected: All tests PASS

- [ ] **Step 4: Commit**

```bash
git add tests/test_integration.py
git commit -m "test: end-to-end integration tests for Phase 1"
```

- [ ] **Step 5: Add .gitignore and README**

Create `.gitignore` (Python standard: `__pycache__/`, `*.egg-info/`, `.venv/`, `dist/`, `build/`). No README required beyond what's in the design doc.

- [ ] **Step 6: Final commit**

```bash
git add .gitignore
git commit -m "chore: add gitignore"
```
