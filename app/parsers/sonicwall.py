"""Stub parser for SonicWall configurations."""

import logging

from app.models import FirewallRule
from app.parsers.base import BaseParser

logger = logging.getLogger(__name__)


class SonicWallParser(BaseParser):
    vendor_name = "SonicWall"

    @staticmethod
    def can_parse(file_content: str) -> bool:
        return False

    def parse(self, file_content: str) -> list[FirewallRule]:
        raise NotImplementedError("SonicWall parser is planned for a future release")
