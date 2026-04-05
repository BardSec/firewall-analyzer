"""Detect shadowed firewall rules.

A rule is shadowed when a preceding rule matches all the same traffic,
making the later rule unreachable.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

from app.models import FirewallRule, Finding
from app.analysis.network_utils import (
    addr_is_subset,
    service_is_subset,
    zones_overlap,
)

logger = logging.getLogger(__name__)


def _is_shadowed_by(later: FirewallRule, earlier: FirewallRule) -> bool:
    """Return True if *earlier* fully shadows *later*.

    All of later's match criteria must be a subset of earlier's.
    """
    try:
        return (
            zones_overlap(later.src_zones, earlier.src_zones)
            and zones_overlap(later.dst_zones, earlier.dst_zones)
            and addr_is_subset(later.src_addrs, earlier.src_addrs)
            and addr_is_subset(later.dst_addrs, earlier.dst_addrs)
            and service_is_subset(later.services, earlier.services)
        )
    except Exception:
        logger.debug(
            "Error comparing rule %s vs %s — skipping pair",
            later.id,
            earlier.id,
            exc_info=True,
        )
        return False


def detect_shadowed_rules(rules: list[FirewallRule]) -> list[Finding]:
    """Return findings for every rule that is fully shadowed by a preceding rule."""
    if not rules:
        return []

    findings: list[Finding] = []
    enabled = [r for r in rules if r.enabled]
    enabled.sort(key=lambda r: r.position)

    for i, rule_b in enumerate(enabled):
        for rule_a in enabled[:i]:
            if not _is_shadowed_by(rule_b, rule_a):
                continue

            actions_differ = rule_b.action != rule_a.action

            if actions_differ:
                severity = "HIGH"
                description = (
                    f"Rule '{rule_b.name}' (#{rule_b.position}) will never be "
                    f"evaluated because rule '{rule_a.name}' (#{rule_a.position}) "
                    f"matches all the same traffic with a different action "
                    f"({rule_a.action} vs {rule_b.action})."
                )
                recommendation = (
                    f"Move rule #{rule_b.position} before #{rule_a.position} "
                    f"if the different action is intended"
                )
            else:
                severity = "MEDIUM"
                description = (
                    f"Rule '{rule_b.name}' (#{rule_b.position}) is dead weight — "
                    f"rule '{rule_a.name}' (#{rule_a.position}) already matches "
                    f"all the same traffic with the same action ({rule_a.action})."
                )
                recommendation = f"Remove or reorder rule #{rule_b.position}"

            findings.append(
                Finding(
                    finding_type="shadow",
                    severity=severity,
                    title=(
                        f"Rule '{rule_b.name}' (#{rule_b.position}) is shadowed "
                        f"by '{rule_a.name}' (#{rule_a.position})"
                    ),
                    description=description,
                    rule_ids=[rule_a.id, rule_b.id],
                    recommendation=recommendation,
                )
            )
            # Only report the first (closest) shadow for each rule
            break

    logger.debug("Shadowing analysis found %d findings", len(findings))
    return findings
