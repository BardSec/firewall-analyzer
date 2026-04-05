"""Detect redundant firewall rules.

A rule is redundant when it can be removed without changing the effective
policy — either because a preceding rule already covers the same traffic
with the same action, or because it is an exact duplicate of another rule.
"""

from __future__ import annotations

import logging

from app.models import FirewallRule, Finding
from app.analysis.network_utils import (
    addr_is_subset,
    service_is_subset,
    zones_overlap,
)

logger = logging.getLogger(__name__)


def _rule_signature(rule: FirewallRule) -> tuple:
    """Return a hashable signature for duplicate detection.

    Two rules with the same signature have identical match criteria and action.
    """
    return (
        tuple(sorted(rule.src_zones)),
        tuple(sorted(rule.dst_zones)),
        tuple(sorted(rule.src_addrs)),
        tuple(sorted(rule.dst_addrs)),
        tuple(sorted(rule.services)),
        rule.action,
    )


def _is_subset_of(later: FirewallRule, earlier: FirewallRule) -> bool:
    """Return True if *earlier* fully covers *later*'s traffic."""
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
            "Error comparing rule %s vs %s", later.id, earlier.id, exc_info=True
        )
        return False


def detect_redundant_rules(rules: list[FirewallRule]) -> list[Finding]:
    """Return findings for redundant and duplicate rules."""
    if not rules:
        return []

    findings: list[Finding] = []
    enabled = [r for r in rules if r.enabled]
    enabled.sort(key=lambda r: r.position)

    # --- Exact-duplicate detection ---
    sig_map: dict[tuple, list[FirewallRule]] = {}
    for rule in enabled:
        sig = _rule_signature(rule)
        sig_map.setdefault(sig, []).append(rule)

    reported_duplicate_ids: set[str] = set()
    for sig, group in sig_map.items():
        if len(group) < 2:
            continue
        first = group[0]
        for dup in group[1:]:
            reported_duplicate_ids.add(dup.id)
            findings.append(
                Finding(
                    finding_type="redundant",
                    severity="MEDIUM",
                    title=(
                        f"Rule '{dup.name}' (#{dup.position}) is an exact "
                        f"duplicate of '{first.name}' (#{first.position})"
                    ),
                    description=(
                        f"Both rules have identical source/destination zones, "
                        f"addresses, services, and action ({first.action})."
                    ),
                    rule_ids=[first.id, dup.id],
                    recommendation=(
                        f"Safe to remove rule #{dup.position} — "
                        f"it has no effect on traffic flow"
                    ),
                )
            )

    # --- Same-action shadowing (redundancy) ---
    for i, rule_b in enumerate(enabled):
        if rule_b.id in reported_duplicate_ids:
            continue
        for rule_a in enabled[:i]:
            if rule_a.action != rule_b.action:
                continue
            if not _is_subset_of(rule_b, rule_a):
                continue

            findings.append(
                Finding(
                    finding_type="redundant",
                    severity="LOW",
                    title=(
                        f"Rule '{rule_b.name}' (#{rule_b.position}) is redundant "
                        f"— already covered by '{rule_a.name}' (#{rule_a.position})"
                    ),
                    description=(
                        f"Rule '{rule_a.name}' (#{rule_a.position}, {rule_a.action}) "
                        f"already matches all traffic that rule '{rule_b.name}' "
                        f"(#{rule_b.position}, {rule_b.action}) would match."
                    ),
                    rule_ids=[rule_a.id, rule_b.id],
                    recommendation=(
                        f"Safe to remove rule #{rule_b.position} — "
                        f"it has no effect on traffic flow"
                    ),
                )
            )
            # Only report the first covering rule
            break

    logger.debug("Redundancy analysis found %d findings", len(findings))
    return findings
