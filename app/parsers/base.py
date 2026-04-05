"""Base parser interface for all firewall config parsers."""

from abc import ABC, abstractmethod

from app.models import FirewallRule


class BaseParser(ABC):
    """Abstract base class for firewall configuration parsers."""

    vendor_name: str = "Unknown"

    @abstractmethod
    def parse(self, file_content: str) -> list[FirewallRule]:
        """Parse a firewall configuration file and return normalized rules.

        Args:
            file_content: The raw text content of the config file.

        Returns:
            A list of normalized FirewallRule objects.
        """

    @staticmethod
    @abstractmethod
    def can_parse(file_content: str) -> bool:
        """Detect whether this parser can handle the given file content.

        Args:
            file_content: The raw text content of the config file.

        Returns:
            True if this parser recognises the format.
        """
