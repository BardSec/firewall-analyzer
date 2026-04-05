"""Stub parser for Cisco ASA configurations."""

import logging

from app.models import FirewallRule
from app.parsers.base import BaseParser

logger = logging.getLogger(__name__)


class CiscoASAParser(BaseParser):
    vendor_name = "Cisco ASA"

    @staticmethod
    def can_parse(file_content: str) -> bool:
        return False

    def parse(self, file_content: str) -> list[FirewallRule]:
        raise NotImplementedError("Cisco ASA parser is planned for a future release")
