from shiftleft.scanners.registry import ScannerRegistry
from shiftleft.scanners.base import BaseScanner
from shiftleft.models import ScanResult
from shiftleft.config import load_config


def _make_scanner(name, installed=True):
    class S(BaseScanner):
        supported_languages = {"python"}

        def is_installed(self):
            return installed

        def scan(self, files, config):
            return ScanResult(
                scanner=self.name,
                findings=[],
                duration_seconds=0,
                success=True,
                error=None
            )

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


def test_get_for_tier():
    reg = ScannerRegistry()
    reg.register(_make_scanner("semgrep"))
    reg.register(_make_scanner("bandit"))
    config = load_config(None)
    # semgrep and bandit are tier 1 in default config
    tier_1_scanners = reg.get_for_tier(1, config)
    names = [s.name for s in tier_1_scanners]
    assert "semgrep" in names
    assert "bandit" in names
    # tier 2 should be empty
    tier_2_scanners = reg.get_for_tier(2, config)
    assert len(tier_2_scanners) == 0
