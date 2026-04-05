"""CIDR, service, and zone matching utilities for firewall rule analysis."""

import ipaddress
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.models import FirewallRule

logger = logging.getLogger(__name__)

# ── Common service name → port notation mapping ─────────────────────────
COMMON_SERVICES: dict[str, str] = {
    "HTTP": "tcp/80",
    "HTTPS": "tcp/443",
    "DNS": "udp/53",
    "SSH": "tcp/22",
    "FTP": "tcp/21",
    "SMTP": "tcp/25",
    "RDP": "tcp/3389",
    "TELNET": "tcp/23",
    "SNMP": "udp/161",
    "NTP": "udp/123",
    "DHCP": "udp/67-68",
    "IMAP": "tcp/143",
    "POP3": "tcp/110",
    "ALL": "any",
    "ALL_TCP": "tcp/1-65535",
    "ALL_UDP": "udp/1-65535",
}


# ── Service helpers ──────────────────────────────────────────────────────

def parse_service(svc: str) -> tuple[str, int, int]:
    """Parse a service string into (protocol, port_low, port_high).

    Examples:
        "tcp/80"      -> ("tcp", 80, 80)
        "tcp/80-443"  -> ("tcp", 80, 443)
        "any"         -> ("any", 0, 65535)
    """
    svc = svc.strip().lower()
    if svc == "any":
        return ("any", 0, 65535)
    if "/" not in svc:
        # Try common-service lookup before giving up
        upper = svc.upper()
        if upper in COMMON_SERVICES:
            return parse_service(COMMON_SERVICES[upper])
        logger.warning("Unrecognised service format: %s – treating as any", svc)
        return ("any", 0, 65535)

    proto, port_part = svc.split("/", 1)
    if "-" in port_part:
        lo_s, hi_s = port_part.split("-", 1)
        try:
            return (proto, int(lo_s), int(hi_s))
        except ValueError:
            logger.warning("Bad port range in service '%s'", svc)
            return (proto, 0, 65535)
    try:
        port = int(port_part)
        return (proto, port, port)
    except ValueError:
        logger.warning("Bad port number in service '%s'", svc)
        return (proto, 0, 65535)


def _service_ranges_overlap(a: tuple[str, int, int], b: tuple[str, int, int]) -> bool:
    """Check whether two parsed service tuples overlap."""
    pa, lo_a, hi_a = a
    pb, lo_b, hi_b = b
    if pa != "any" and pb != "any" and pa != pb:
        return False
    return lo_a <= hi_b and lo_b <= hi_a


def _service_range_subset(inner: tuple[str, int, int], outer: tuple[str, int, int]) -> bool:
    """Check whether *inner* is fully contained in *outer*."""
    pi, lo_i, hi_i = inner
    po, lo_o, hi_o = outer
    if po != "any" and pi != po:
        return False
    return lo_o <= lo_i and hi_i <= hi_o


def services_overlap(svcs_a: list[str], svcs_b: list[str]) -> bool:
    """Return True if any service in *svcs_a* overlaps any service in *svcs_b*."""
    parsed_a = [parse_service(s) for s in svcs_a]
    parsed_b = [parse_service(s) for s in svcs_b]
    return any(
        _service_ranges_overlap(a, b)
        for a in parsed_a
        for b in parsed_b
    )


def service_is_subset(svcs_a: list[str], svcs_b: list[str]) -> bool:
    """Return True if every service in *svcs_a* is covered by some service in *svcs_b*."""
    parsed_a = [parse_service(s) for s in svcs_a]
    parsed_b = [parse_service(s) for s in svcs_b]
    return all(
        any(_service_range_subset(a, b) for b in parsed_b)
        for a in parsed_a
    )


# ── CIDR / address helpers ──────────────────────────────────────────────

def _to_network(addr: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """Parse a string to an IP network, treating bare IPs as /32 or /128."""
    return ipaddress.ip_network(addr, strict=False)


def cidr_contains(supernet: str, subnet: str) -> bool:
    """Return True if *supernet* fully contains *subnet*."""
    try:
        sup = _to_network(supernet)
        sub = _to_network(subnet)
        return sub.subnet_of(sup)
    except ValueError:
        logger.warning("Invalid CIDR comparison: %s vs %s", supernet, subnet)
        return False


def cidrs_overlap(a: str, b: str) -> bool:
    """Return True if the two CIDRs share any addresses."""
    try:
        net_a = _to_network(a)
        net_b = _to_network(b)
        return net_a.overlaps(net_b)
    except ValueError:
        logger.warning("Invalid CIDR overlap check: %s vs %s", a, b)
        return False


def addr_is_subset(addrs_a: list[str], addrs_b: list[str]) -> bool:
    """Return True if every address/CIDR in *addrs_a* is covered by some entry in *addrs_b*.

    The literal string ``"any"`` covers everything.
    """
    if "any" in (a.lower() for a in addrs_b):
        return True
    if "any" in (a.lower() for a in addrs_a):
        # "any" is only covered by "any" (handled above)
        return False
    for a in addrs_a:
        try:
            net_a = _to_network(a)
        except ValueError:
            # Non-CIDR value (e.g. FQDN) — only exact match counts
            if a not in addrs_b:
                return False
            continue
        if not any(_safe_subnet_of(net_a, b) for b in addrs_b):
            return False
    return True


def _safe_subnet_of(
    net: ipaddress.IPv4Network | ipaddress.IPv6Network, addr_str: str
) -> bool:
    try:
        return net.subnet_of(_to_network(addr_str))
    except (ValueError, TypeError):
        return False


# ── Zone helpers ─────────────────────────────────────────────────────────

def zones_overlap(zones_a: list[str], zones_b: list[str]) -> bool:
    """Return True if the two zone lists overlap.  ``"any"`` matches all."""
    lower_a = {z.lower() for z in zones_a}
    lower_b = {z.lower() for z in zones_b}
    if "any" in lower_a or "any" in lower_b:
        return True
    return bool(lower_a & lower_b)


# ── High-level rule check ───────────────────────────────────────────────

def is_broadly_permissive(rule: "FirewallRule") -> tuple[bool, str]:
    """Detect whether a rule is overly permissive.

    Returns:
        (True, reason) if the rule is broadly permissive, otherwise (False, "").
    """
    if rule.action.lower() not in ("allow", "accept", "permit"):
        return (False, "")

    src_any = any(a.lower() == "any" for a in rule.src_addrs)
    dst_any = any(a.lower() == "any" for a in rule.dst_addrs)
    svc_any = any(s.lower() == "any" for s in rule.services)

    # any/any/any allow
    if src_any and dst_any and svc_any:
        return (True, "Rule allows any source to any destination on any service")

    # Large source or destination CIDRs (/8 or larger)
    for label, addrs in [("source", rule.src_addrs), ("destination", rule.dst_addrs)]:
        for addr in addrs:
            if addr.lower() == "any":
                continue
            try:
                net = _to_network(addr)
                if net.prefixlen <= 8:
                    return (
                        True,
                        f"Rule uses a /{net.prefixlen} {label} network ({addr}), "
                        f"which is very broad",
                    )
            except ValueError:
                continue

    # any source + any service, or any destination + any service
    if src_any and svc_any:
        return (True, "Rule allows any source on any service")
    if dst_any and svc_any:
        return (True, "Rule allows any service to any destination")

    return (False, "")
