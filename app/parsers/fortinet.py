"""Parser for FortiGate / FortiOS firewall configurations."""

import logging
import re

from app.analysis.network_utils import COMMON_SERVICES
from app.models import FirewallRule
from app.parsers.base import BaseParser

logger = logging.getLogger(__name__)


class FortinetParser(BaseParser):
    vendor_name = "Fortinet FortiGate"

    @staticmethod
    def can_parse(file_content: str) -> bool:
        return (
            "config firewall policy" in file_content
            or "set srcintf" in file_content
        )

    # ── public API ───────────────────────────────────────────────────────

    def parse(self, file_content: str) -> list[FirewallRule]:
        addresses = self._parse_addresses(file_content)
        services = self._parse_services(file_content)
        return self._parse_policies(file_content, addresses, services)

    # ── address object parsing ───────────────────────────────────────────

    @staticmethod
    def _parse_addresses(content: str) -> dict[str, str]:
        """Build a name -> CIDR/FQDN lookup from ``config firewall address``."""
        lookup: dict[str, str] = {}
        block = _extract_config_block(content, "config firewall address")
        if not block:
            return lookup
        for name, body in _iter_edit_blocks(block):
            subnet_m = re.search(r'set subnet\s+(\S+)\s+(\S+)', body)
            if subnet_m:
                ip, mask = subnet_m.group(1), subnet_m.group(2)
                lookup[name] = _mask_to_cidr(ip, mask)
                continue
            fqdn_m = re.search(r'set fqdn\s+"?([^"\s]+)"?', body)
            if fqdn_m:
                lookup[name] = fqdn_m.group(1)
                continue
            # set type ipmask with set subnet already handled; skip others
        return lookup

    # ── service object parsing ───────────────────────────────────────────

    @staticmethod
    def _parse_services(content: str) -> dict[str, str]:
        """Build a name -> port-notation lookup from ``config firewall service custom``."""
        lookup: dict[str, str] = {}
        block = _extract_config_block(content, "config firewall service custom")
        if not block:
            return lookup
        for name, body in _iter_edit_blocks(block):
            proto_m = re.search(r'set protocol\s+(\S+)', body)
            proto = proto_m.group(1).lower() if proto_m else "tcp"
            # TCP/UDP port ranges
            port_m = re.search(r'set (?:tcp|udp)-portrange\s+(.+)', body)
            if port_m:
                raw = port_m.group(1).strip().split()[0]  # first range
                port_str = raw.split(":")[0]  # strip source-port part
                lookup[name] = f"{proto}/{port_str}"
                continue
            # ICMP or protocol-number entries are kept as-is
            if proto in ("icmp", "icmp6"):
                lookup[name] = f"{proto}/0-65535"
        return lookup

    # ── policy parsing ───────────────────────────────────────────────────

    def _parse_policies(
        self,
        content: str,
        addresses: dict[str, str],
        services: dict[str, str],
    ) -> list[FirewallRule]:
        rules: list[FirewallRule] = []
        block = _extract_config_block(content, "config firewall policy")
        if not block:
            logger.warning("No 'config firewall policy' block found")
            return rules

        for position, (edit_id, body) in enumerate(_iter_edit_blocks(block), start=1):
            try:
                rule = self._parse_single_policy(
                    edit_id, body, position, addresses, services,
                )
                if rule is not None:
                    rules.append(rule)
            except Exception:
                logger.warning("Skipping malformed policy edit %s", edit_id, exc_info=True)
        return rules

    def _parse_single_policy(
        self,
        edit_id: str,
        body: str,
        position: int,
        addresses: dict[str, str],
        services: dict[str, str],
    ) -> FirewallRule | None:
        def _get(key: str) -> str:
            m = re.search(rf'set {key}\s+"?([^"\n]+)"?', body)
            return m.group(1).strip() if m else ""

        def _get_list(key: str) -> list[str]:
            m = re.search(rf'set {key}\s+(.+)', body)
            if not m:
                return []
            raw = m.group(1).strip()
            # Values may be quoted individually: "a" "b"
            quoted = re.findall(r'"([^"]+)"', raw)
            return quoted if quoted else raw.split()

        name = _get("name") or f"policy-{edit_id}"
        srcintf = _get_list("srcintf") or ["any"]
        dstintf = _get_list("dstintf") or ["any"]
        srcaddr_names = _get_list("srcaddr") or ["all"]
        dstaddr_names = _get_list("dstaddr") or ["all"]
        service_names = _get_list("service") or ["ALL"]
        action_raw = _get("action").lower() or "deny"
        status_raw = _get("status").lower()
        logtraffic = _get("logtraffic").lower()

        # Normalise action
        action = "allow" if action_raw == "accept" else "deny"

        # Resolve addresses
        src_addrs = self._resolve_addrs(srcaddr_names, addresses)
        dst_addrs = self._resolve_addrs(dstaddr_names, addresses)

        # Resolve services
        svc_list = self._resolve_services(service_names, services)

        enabled = status_raw != "disable"
        logging_on = logtraffic not in ("", "disable")

        return FirewallRule(
            id=edit_id,
            name=name,
            enabled=enabled,
            action=action,
            src_zones=srcintf,
            dst_zones=dstintf,
            src_addrs=src_addrs,
            dst_addrs=dst_addrs,
            services=svc_list,
            logging=logging_on,
            position=position,
        )

    # ── resolution helpers ───────────────────────────────────────────────

    @staticmethod
    def _resolve_addrs(names: list[str], lookup: dict[str, str]) -> list[str]:
        resolved: list[str] = []
        for n in names:
            low = n.lower()
            if low in ("all", "any"):
                resolved.append("any")
            elif n in lookup:
                resolved.append(lookup[n])
            else:
                logger.debug("Address '%s' not in lookup, using raw name", n)
                resolved.append(n)
        return resolved

    @staticmethod
    def _resolve_services(names: list[str], lookup: dict[str, str]) -> list[str]:
        resolved: list[str] = []
        for n in names:
            low = n.lower()
            if low in ("all", "any"):
                resolved.append("any")
                continue
            if n in lookup:
                resolved.append(lookup[n])
                continue
            upper = n.upper().replace(" ", "_")
            if upper in COMMON_SERVICES:
                resolved.append(COMMON_SERVICES[upper])
                continue
            logger.debug("Service '%s' not resolved, using raw name", n)
            resolved.append(n)
        return resolved


# ── internal helpers ─────────────────────────────────────────────────────

def _extract_config_block(content: str, header: str) -> str | None:
    """Extract the text between a ``config ...`` header and its matching ``end``."""
    start = content.find(header)
    if start == -1:
        return None
    depth = 1
    pos = start + len(header)
    while pos < len(content) and depth > 0:
        # Find next config or end keyword at start of line
        m = re.search(r'^(config |end)\b', content[pos:], re.MULTILINE)
        if not m:
            break
        keyword = m.group(1).strip()
        pos += m.start() + len(m.group(0))
        if keyword == "config":
            depth += 1
        else:
            depth -= 1
    return content[start:pos]


def _iter_edit_blocks(block: str):
    """Yield (edit_id, body_text) for each ``edit <id> ... next`` in *block*."""
    pattern = re.compile(
        r'edit\s+"?(\S+?)"?\s*\n(.*?)(?=\bnext\b)',
        re.DOTALL,
    )
    for m in pattern.finditer(block):
        yield m.group(1), m.group(2)


def _mask_to_cidr(ip: str, mask: str) -> str:
    """Convert an IP + dotted-decimal mask to CIDR notation."""
    try:
        import ipaddress as _ip
        net = _ip.ip_network(f"{ip}/{mask}", strict=False)
        return str(net)
    except ValueError:
        return f"{ip}/{mask}"
