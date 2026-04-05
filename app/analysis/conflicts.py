"""Detect conflicting firewall rules.

Two rules conflict when they match overlapping traffic but specify
different actions — one allows what the other denies (or drops).
"""

from __future__ import annotations

import logging

from app.models import FirewallRule, Finding
from app.analysis.network_utils import (
    addr_is_subset,
    cidrs_overlap,
    service_is_subset,
    services_overlap,
    zones_overlap,
)

logger = logging.getLogger(__name__)


def _one_shadows_other(a: FirewallRule, b: FirewallRule) -> bool:
    """Return True if one rule fully shadows the other (in either direction).

    Conflicts should not be reported for pairs that are better described
    as shadowing issues.
    """
    try:
        a_shadows_b = (
            zones_overlap(b.src_zones, a.src_zones)
            and zones_overlap(b.dst_zones, a.dst_zones)
            and addr_is_subset(b.src_addrs, a.src_addrs)
            and addr_is_subset(b.dst_addrs, a.dst_addrs)
            and service_is_subset(b.services, a.services)
        )
        b_shadows_a = (
            zones_overlap(a.src_zones, b.src_zones)
            and zones_overlap(a.dst_zones, b.dst_zones)
            and addr_is_subset(a.src_addrs, b.src_addrs)
            and addr_is_subset(a.dst_addrs, b.dst_addrs)
            and service_is_subset(a.services, b.services)
        )
        return a_shadows_b or b_shadows_a
    except Exception:
        logger.debug(
            "Error checking shadow between %s and %s", a.id, b.id, exc_info=True
        )
        return False


def _rules_overlap(a: FirewallRule, b: FirewallRule) -> bool:
    """Return True if the two rules match overlapping traffic in all dimensions."""
    try:
        return (
            zones_overlap(a.src_zones, b.src_zones)
            and zones_overlap(a.dst_zones, b.dst_zones)
            and cidrs_overlap(a.src_addrs, b.src_addrs)
            and cidrs_overlap(a.dst_addrs, b.dst_addrs)
            and services_overlap(a.services, b.services)
        )
    except Exception:
        logger.debug(
            "Error checking overlap between %s and %s", a.id, b.id, exc_info=True
        )
        return False


def detect_conflicts(rules: list[FirewallRule]) -> list[Finding]:
    """Return findings for every pair of enabled rules with conflicting actions
    and overlapping match criteria."""
    if not rules:
        return []

    findings: list[Finding] = []
    enabled = [r for r in rules if r.enabled]
    enabled.sort(key=lambda r: r.position)
    seen_pairs: set[tuple[str, str]] = set()

    for i, rule_a in enumerate(enabled):
        for rule_b in enabled[i + 1 :]:
            # Only look at rules with different actions
            if rule_a.action == rule_b.action:
                continue

            pair_key = (rule_a.id, rule_b.id)
            if pair_key in seen_pairs:
                continue
            seen_pairs.add(pair_key)

            if not _rules_overlap(rule_a, rule_b):
                continue

            # Skip if one fully shadows the other — that belongs in shadowing
            if _one_shadows_other(rule_a, rule_b):
                continue

            # Determine severity
            actions = {rule_a.action, rule_b.action}
            if "allow" in actions and ("deny" in actions or "drop" in actions):
                severity = "CRITICAL"
            else:
                severity = "HIGH"

            findings.append(
                Finding(
                    finding_type="conflict",
                    severity=severity,
                    title=(
                        f"Conflict between '{rule_a.name}' (#{rule_a.position}) "
                        f"and '{rule_b.name}' (#{rule_b.position})"
                    ),
                    description=(
                        f"Rules '{rule_a.name}' ({rule_a.action}) and "
                        f"'{rule_b.name}' ({rule_b.action}) match overlapping "
                        f"traffic but take different actions. The effective "
                        f"behavior depends on rule order."
                    ),
                    rule_ids=[rule_a.id, rule_b.id],
                    recommendation=(
                        f"Review rules #{rule_a.position} and #{rule_b.position} "
                        f"— tighten the match criteria so they no longer overlap, "
                        f"or document the intended precedence."
                    ),
                )
            )

    logger.debug("Conflict analysis found %d findings", len(findings))
    return findings
