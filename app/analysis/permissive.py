"""Detect overly permissive firewall rules.

Flags rules that allow too much traffic — critical for K-12 environments
where E-Rate and CIPA compliance require tight controls and logging.
"""

from __future__ import annotations

import logging

from app.models import FirewallRule, Finding
from app.analysis.network_utils import is_broadly_permissive, parse_service

logger = logging.getLogger(__name__)


def _is_any(addrs: list[str]) -> bool:
    """Return True if the address list effectively means 'any'."""
    if not addrs:
        return False
    normalized = [a.strip().lower() for a in addrs]
    return "any" in normalized or "0.0.0.0/0" in normalized


def _is_any_service(services: list[str]) -> bool:
    """Return True if the service list effectively means 'any'."""
    if not services:
        return False
    normalized = [s.strip().lower() for s in services]
    return "any" in normalized


def _has_broad_cidr(addrs: list[str]) -> list[str]:
    """Return address entries that use a /8 or larger CIDR."""
    broad: list[str] = []
    for addr in addrs:
        addr_stripped = addr.strip().lower()
        if addr_stripped == "any":
            continue
        try:
            if is_broadly_permissive(addr_stripped):
                broad.append(addr)
        except Exception:
            logger.debug("Could not evaluate breadth of '%s'", addr, exc_info=True)
    return broad


def detect_permissive_rules(rules: list[FirewallRule]) -> list[Finding]:
    """Return findings for overly permissive allow rules."""
    if not rules:
        return []

    findings: list[Finding] = []

    for rule in rules:
        if not rule.enabled:
            continue
        if rule.action != "allow":
            continue

        any_src = _is_any(rule.src_addrs)
        any_dst = _is_any(rule.dst_addrs)
        any_svc = _is_any_service(rule.services)

        # CRITICAL — any/any/any
        if any_src and any_dst and any_svc:
            findings.append(
                Finding(
                    finding_type="permissive",
                    severity="CRITICAL",
                    title=f"Rule '{rule.name}' (#{rule.position}) allows all traffic",
                    description=(
                        "This rule permits any source to reach any destination "
                        "on any service. It effectively disables the firewall "
                        "for matched zones."
                    ),
                    rule_ids=[rule.id],
                    recommendation=(
                        "Replace with specific source/destination/service rules. "
                        "An any/any/any allow rule is almost never appropriate."
                    ),
                )
            )
            # Still check logging below, but skip the less severe checks
            _check_logging(rule, findings)
            continue

        # HIGH — any source OR any destination with any service
        if (any_src or any_dst) and any_svc:
            side = "source" if any_src else "destination"
            findings.append(
                Finding(
                    finding_type="permissive",
                    severity="HIGH",
                    title=f"Rule '{rule.name}' (#{rule.position}) is overly broad",
                    description=(
                        f"Any {side} address combined with any service makes "
                        f"this rule very permissive."
                    ),
                    rule_ids=[rule.id],
                    recommendation=(
                        f"Restrict the {side} addresses and/or limit the "
                        f"allowed services to only what is needed."
                    ),
                )
            )

        # MEDIUM — broad CIDR (/8 or larger)
        broad_src = _has_broad_cidr(rule.src_addrs)
        broad_dst = _has_broad_cidr(rule.dst_addrs)
        if broad_src or broad_dst:
            broad_all = broad_src + broad_dst
            findings.append(
                Finding(
                    finding_type="permissive",
                    severity="MEDIUM",
                    title=(
                        f"Rule '{rule.name}' (#{rule.position}) uses a broad "
                        f"network range"
                    ),
                    description=(
                        f"Address(es) {', '.join(broad_all)} cover a very large "
                        f"network block (/8 or larger)."
                    ),
                    rule_ids=[rule.id],
                    recommendation=(
                        "Narrow the CIDR range to only the networks that "
                        "actually need access."
                    ),
                )
            )

        # MEDIUM — any service with specific src/dst
        if any_svc and not any_src and not any_dst:
            findings.append(
                Finding(
                    finding_type="permissive",
                    severity="MEDIUM",
                    title=(
                        f"Rule '{rule.name}' (#{rule.position}) opens all services"
                    ),
                    description=(
                        "All services are allowed between specific endpoints. "
                        "This may expose unnecessary ports."
                    ),
                    rule_ids=[rule.id],
                    recommendation=(
                        "Limit services to only the protocols and ports that "
                        "are required."
                    ),
                )
            )

        # LOW — missing logging
        _check_logging(rule, findings)

    logger.debug("Permissive analysis found %d findings", len(findings))
    return findings


def _check_logging(rule: FirewallRule, findings: list[Finding]) -> None:
    """Append a finding if an allow rule has logging disabled."""
    if rule.logging:
        return

    findings.append(
        Finding(
            finding_type="permissive",
            severity="LOW",
            title=(
                f"Rule '{rule.name}' (#{rule.position}) — allow rule without logging"
            ),
            description=(
                "Allow rules should have logging enabled so that traffic can "
                "be audited. E-Rate and CIPA compliance in K-12 environments "
                "require visibility into allowed traffic."
            ),
            rule_ids=[rule.id],
            recommendation=(
                "Enable logging on this rule to maintain compliance and "
                "support incident investigation."
            ),
        )
    )
