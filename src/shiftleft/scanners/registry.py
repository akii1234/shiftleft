from shiftleft.scanners.base import BaseScanner
from shiftleft.config import ShiftLeftConfig


class ScannerRegistry:
    """Registry for managing scanner instances."""

    def __init__(self):
        """Initialize an empty scanner registry."""
        self._scanners: dict[str, BaseScanner] = {}

    def register(self, scanner: BaseScanner) -> None:
        """
        Register a scanner instance.

        Args:
            scanner: BaseScanner instance to register
        """
        self._scanners[scanner.name] = scanner

    def get_enabled(self, config: ShiftLeftConfig) -> list[BaseScanner]:
        """
        Get all enabled and installed scanners.

        A scanner is enabled if:
        1. It is registered in the registry
        2. Its configuration has enabled=True
        3. The scanner's is_installed() returns True

        Args:
            config: ShiftLeftConfig containing scanner configurations

        Returns:
            List of enabled BaseScanner instances
        """
        enabled = []
        for name, scanner in self._scanners.items():
            # Check if scanner is in config and enabled
            if name in config.scanners:
                scanner_config = config.scanners[name]
                if scanner_config.enabled and scanner.is_installed():
                    enabled.append(scanner)
        return enabled

    def get_for_tier(self, tier: int, config: ShiftLeftConfig) -> list[BaseScanner]:
        """
        Get all enabled and installed scanners for a specific tier.

        A scanner is included if:
        1. It is registered in the registry
        2. Its configuration has the specified tier
        3. Its configuration has enabled=True
        4. The scanner's is_installed() returns True

        Args:
            tier: Tier number to filter by
            config: ShiftLeftConfig containing scanner configurations

        Returns:
            List of enabled BaseScanner instances for the given tier
        """
        scanners_for_tier = []
        for name, scanner in self._scanners.items():
            # Check if scanner is in config and matches tier
            if name in config.scanners:
                scanner_config = config.scanners[name]
                if (scanner_config.tier == tier and
                    scanner_config.enabled and
                    scanner.is_installed()):
                    scanners_for_tier.append(scanner)
        return scanners_for_tier
