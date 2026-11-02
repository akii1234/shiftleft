from abc import ABC, abstractmethod
from pathlib import Path

from shiftleft.models import ScanResult
from shiftleft.config import ScannerConfig


class BaseScanner(ABC):
    """Abstract base class for security scanners."""

    name: str
    supported_languages: set[str]

    @abstractmethod
    def is_installed(self) -> bool:
        """Check if the scanner is installed and available."""
        pass

    @abstractmethod
    def scan(self, files: list[Path], config: ScannerConfig) -> ScanResult:
        """
        Run the scanner on the given files.

        Args:
            files: List of file paths to scan
            config: Scanner-specific configuration

        Returns:
            ScanResult with findings and metadata
        """
        pass

    def filter_files(self, files: list[Path]) -> list[Path]:
        """
        Filter files by supported languages.

        Default implementation returns all files.
        Subclasses can override to filter by language.

        Args:
            files: List of file paths

        Returns:
            Filtered list of file paths
        """
        return files
