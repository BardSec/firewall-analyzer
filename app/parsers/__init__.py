"""Parser registry — auto-detection and vendor listing."""

from app.parsers.base import BaseParser
from app.parsers.cisco_asa import CiscoASAParser
from app.parsers.fortinet import FortinetParser
from app.parsers.meraki import MerakiParser
from app.parsers.mikrotik import MikroTikParser
from app.parsers.paloalto import PaloAltoParser
from app.parsers.pfsense import PfSenseParser
from app.parsers.sonicwall import SonicWallParser

# Ordered by detection priority — more specific signatures first.
PARSERS: list[type[BaseParser]] = [
    FortinetParser,
    PaloAltoParser,
    PfSenseParser,
    CiscoASAParser,
    MerakiParser,
    MikroTikParser,
    SonicWallParser,
]

SUPPORTED_VENDORS: list[str] = [p.vendor_name for p in PARSERS]


def auto_detect_vendor(content: str) -> BaseParser | None:
    """Return an instantiated parser for the first vendor that matches, or None."""
    for parser_cls in PARSERS:
        try:
            if parser_cls.can_parse(content):
                return parser_cls()
        except Exception:
            continue
    return None
