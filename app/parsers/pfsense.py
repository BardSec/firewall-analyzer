"""Parser for pfSense XML configurations."""

import logging
import xml.etree.ElementTree as ET

from app.models import FirewallRule
from app.parsers.base import BaseParser

logger = logging.getLogger(__name__)


class PfSenseParser(BaseParser):
    vendor_name = "pfSense"

    @staticmethod
    def can_parse(file_content: str) -> bool:
        return "<pfsense>" in file_content.lower()

    # ── public API ───────────────────────────────────────────────────────

    def parse(self, file_content: str) -> list[FirewallRule]:
        try:
            root = ET.fromstring(file_content)
        except ET.ParseError as exc:
            logger.error("Failed to parse pfSense XML: %s", exc)
            return []

        aliases = self._parse_aliases(root)
        rules: list[FirewallRule] = []

        filter_el = root.find("filter")
        if filter_el is None:
            logger.warning("No <filter> element found in pfSense config")
            return rules

        for position, rule_el in enumerate(filter_el.findall("rule"), start=1):
            try:
                rule = self._parse_rule(rule_el, position, aliases)
                if rule is not None:
                    rules.append(rule)
            except Exception:
                logger.warning(
                    "Skipping malformed pfSense rule at position %d", position,
                    exc_info=True,
                )
        return rules

    # ── alias parsing ────────────────────────────────────────────────────

    @staticmethod
    def _parse_aliases(root: ET.Element) -> dict[str, list[str]]:
        """Build a name -> list[address] lookup from ``<aliases><alias>``."""
        lookup: dict[str, list[str]] = {}
        aliases_el = root.find("aliases")
        if aliases_el is None:
            return lookup
        for alias in aliases_el.findall("alias"):
            name = alias.findtext("name", "").strip()
            if not name:
                continue
            address_text = alias.findtext("address", "").strip()
            if address_text:
                lookup[name] = [a.strip() for a in address_text.split(" ") if a.strip()]
        return lookup

    # ── single rule parsing ──────────────────────────────────────────────

    def _parse_rule(
        self,
        rule_el: ET.Element,
        position: int,
        aliases: dict[str, list[str]],
    ) -> FirewallRule | None:
        rule_type = rule_el.findtext("type", "pass").strip().lower()
        interface = rule_el.findtext("interface", "any").strip()
        protocol = rule_el.findtext("protocol", "any").strip().lower()

        # Disabled?
        disabled_el = rule_el.find("disabled")
        enabled = disabled_el is None  # presence of <disabled/> means disabled

        # Description as name
        descr = rule_el.findtext("descr", "").strip()
        tracker = rule_el.findtext("tracker", "").strip()
        rule_id = tracker or str(position)
        name = descr or f"rule-{rule_id}"

        # Source
        src_addrs = self._parse_endpoint(rule_el.find("source"), aliases)
        dst_addrs = self._parse_endpoint(rule_el.find("destination"), aliases)

        # Destination port -> service notation
        services = self._parse_services(rule_el, protocol)

        # Normalise action
        if rule_type == "pass":
            action = "allow"
        elif rule_type in ("block", "reject"):
            action = "deny"
        else:
            action = rule_type

        # Logging
        log_el = rule_el.find("log")
        logging_on = log_el is not None

        return FirewallRule(
            id=rule_id,
            name=name,
            enabled=enabled,
            action=action,
            src_zones=[interface],
            dst_zones=[interface],
            src_addrs=src_addrs,
            dst_addrs=dst_addrs,
            services=services,
            logging=logging_on,
            position=position,
        )

    # ── endpoint (source/destination) parsing ────────────────────────────

    def _parse_endpoint(
        self,
        ep_el: ET.Element | None,
        aliases: dict[str, list[str]],
    ) -> list[str]:
        if ep_el is None:
            return ["any"]
        # <any/> means any
        if ep_el.find("any") is not None:
            return ["any"]
        # <network> or <address>
        network = ep_el.findtext("network", "").strip()
        address = ep_el.findtext("address", "").strip()
        target = network or address
        if not target:
            return ["any"]
        # Resolve alias
        if target in aliases:
            return aliases[target]
        # Interface-style values like "lan" or "wan" treated as zone labels
        return [target]

    @staticmethod
    def _parse_services(rule_el: ET.Element, protocol: str) -> list[str]:
        """Extract service notation from destination port info."""
        if protocol == "any":
            return ["any"]

        dst_el = rule_el.find("destination")
        if dst_el is None:
            return [f"{protocol}/1-65535"]

        port = dst_el.findtext("port", "").strip()
        if not port:
            return [f"{protocol}/1-65535"]

        # Port can be a single value, range (e.g. "80:443"), or comma list
        services: list[str] = []
        for part in port.split(","):
            part = part.strip().replace(":", "-")
            if part:
                services.append(f"{protocol}/{part}")
        return services or [f"{protocol}/1-65535"]
