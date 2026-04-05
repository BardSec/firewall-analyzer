"""Stub parser for Cisco Meraki configurations."""

import logging

from app.models import FirewallRule
from app.parsers.base import BaseParser

logger = logging.getLogger(__name__)


class MerakiParser(BaseParser):
    vendor_name = "Cisco Meraki"

    @staticmethod
    def can_parse(file_content: str) -> bool:
        return False

    def parse(self, file_content: str) -> list[FirewallRule]:
        raise NotImplementedError("Cisco Meraki parser is planned for a future release")
