"""Stub parser for MikroTik RouterOS configurations."""

import logging

from app.models import FirewallRule
from app.parsers.base import BaseParser

logger = logging.getLogger(__name__)


class MikroTikParser(BaseParser):
    vendor_name = "MikroTik RouterOS"

    @staticmethod
    def can_parse(file_content: str) -> bool:
        return False

    def parse(self, file_content: str) -> list[FirewallRule]:
        raise NotImplementedError("MikroTik RouterOS parser is planned for a future release")
