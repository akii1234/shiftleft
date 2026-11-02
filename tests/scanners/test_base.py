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

        def is_installed(self):
            return True

        def scan(self, files, config):
            return ScanResult(
                scanner=self.name,
                findings=[],
                duration_seconds=0,
                success=True,
                error=None
            )

    s = DummyScanner()
    files = [Path("a.py"), Path("b.js")]
    assert s.filter_files(files) == files
