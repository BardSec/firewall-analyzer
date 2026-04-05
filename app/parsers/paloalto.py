"""Parser for Palo Alto PAN-OS XML configurations."""

import logging
import xml.etree.ElementTree as ET

from app.models import FirewallRule
from app.parsers.base import BaseParser

logger = logging.getLogger(__name__)


class PaloAltoParser(BaseParser):
    vendor_name = "Palo Alto Networks"

    @staticmethod
    def can_parse(file_content: str) -> bool:
        # Quick string checks before attempting XML parse
        return (
            "<config" in file_content
            or "<rulebase>" in file_content
            or "<security>" in file_content
        )

    # ── public API ───────────────────────────────────────────────────────

    def parse(self, file_content: str) -> list[FirewallRule]:
        try:
            root = ET.fromstring(file_content)
        except ET.ParseError as exc:
            logger.error("Failed to parse XML: %s", exc)
            return []

        addresses = self._parse_addresses(root)
        rules: list[FirewallRule] = []

        # Security rules can appear at several paths depending on config scope
        for entry_list in self._find_security_rules(root):
            for position, entry in enumerate(entry_list, start=len(rules) + 1):
                try:
                    rule = self._parse_entry(entry, position, addresses)
                    if rule is not None:
                        rules.append(rule)
                except Exception:
                    name = entry.get("name", "?")
                    logger.warning("Skipping malformed rule '%s'", name, exc_info=True)
        return rules

    # ── address object parsing ───────────────────────────────────────────

    @staticmethod
    def _parse_addresses(root: ET.Element) -> dict[str, str]:
        """Build a name -> CIDR lookup from ``<address>`` objects."""
        lookup: dict[str, str] = {}
        for addr_el in root.iter("address"):
            for entry in addr_el.findall("entry"):
                name = entry.get("name", "")
                if not name:
                    continue
                ip_netmask = entry.findtext("ip-netmask")
                if ip_netmask:
                    lookup[name] = ip_netmask.strip()
                    continue
                ip_range = entry.findtext("ip-range")
                if ip_range:
                    lookup[name] = ip_range.strip()
                    continue
                fqdn = entry.findtext("fqdn")
                if fqdn:
                    lookup[name] = fqdn.strip()
        return lookup

    # ── rule location helpers ────────────────────────────────────────────

    @staticmethod
    def _find_security_rules(root: ET.Element) -> list[list[ET.Element]]:
        """Return lists of ``<entry>`` elements found under security rulebases."""
        results: list[list[ET.Element]] = []

        # Standard XPath patterns used by PAN-OS exported configs
        search_paths = [
            ".//rulebase/security/rules",
            ".//security/rules",
            ".//rules",
        ]
        seen_tags: set[int] = set()
        for path in search_paths:
            for rules_el in root.findall(path):
                tag_id = id(rules_el)
                if tag_id in seen_tags:
                    continue
                seen_tags.add(tag_id)
                entries = rules_el.findall("entry")
                if entries:
                    results.append(entries)
        return results

    # ── single rule parsing ──────────────────────────────────────────────

    def _parse_entry(
        self,
        entry: ET.Element,
        position: int,
        addresses: dict[str, str],
    ) -> FirewallRule | None:
        name = entry.get("name", f"rule-{position}")

        from_zones = _members(entry, "from")
        to_zones = _members(entry, "to")
        src_names = _members(entry, "source")
        dst_names = _members(entry, "destination")
        svc_names = _members(entry, "service")
        action = _text(entry, "action") or "deny"
        disabled = (_text(entry, "disabled") or "no").lower() in ("yes", "true")
        log_end = (_text(entry, "log-end") or "no").lower() in ("yes", "true")

        src_addrs = self._resolve(src_names, addresses)
        dst_addrs = self._resolve(dst_names, addresses)

        # Normalise action
        if action.lower() in ("allow", "accept"):
            action_norm = "allow"
        elif action.lower() in ("deny", "drop", "reset-client", "reset-server", "reset-both"):
            action_norm = "deny"
        else:
            action_norm = action.lower()

        return FirewallRule(
            id=name,
            name=name,
            enabled=not disabled,
            action=action_norm,
            src_zones=from_zones or ["any"],
            dst_zones=to_zones or ["any"],
            src_addrs=src_addrs or ["any"],
            dst_addrs=dst_addrs or ["any"],
            services=svc_names or ["any"],
            logging=log_end,
            position=position,
        )

    @staticmethod
    def _resolve(names: list[str], lookup: dict[str, str]) -> list[str]:
        resolved: list[str] = []
        for n in names:
            if n.lower() == "any":
                resolved.append("any")
            elif n in lookup:
                resolved.append(lookup[n])
            else:
                resolved.append(n)
        return resolved


# ── XML helpers ──────────────────────────────────────────────────────────

def _members(parent: ET.Element, tag: str) -> list[str]:
    """Return a list of ``<member>`` text values under *parent*/*tag*."""
    container = parent.find(tag)
    if container is None:
        return []
    members = container.findall("member")
    if members:
        return [m.text.strip() for m in members if m.text]
    # Fallback: direct text
    if container.text and container.text.strip():
        return [container.text.strip()]
    return []


def _text(parent: ET.Element, tag: str) -> str | None:
    """Return the text of a direct child element, or None."""
    el = parent.find(tag)
    if el is not None and el.text:
        return el.text.strip()
    return None
