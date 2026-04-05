"""Central analysis engine that orchestrates all rule detectors."""

from __future__ import annotations

import logging
from datetime import datetime

from app.models import AnalysisResult, FirewallRule, Finding
from app.analysis.shadowing import detect_shadowed_rules
from app.analysis.conflicts import detect_conflicts
from app.analysis.redundant import detect_redundant_rules
from app.analysis.permissive import detect_permissive_rules

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _sort_findings(findings: list[Finding]) -> list[Finding]:
    """Sort findings by severity (CRITICAL first), stable within each level."""
    return sorted(findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))


class AnalysisEngine:
    """Run all analysis detectors against a set of normalized firewall rules."""

    def analyze(
        self,
        rules: list[FirewallRule],
        vendor: str,
        filename: str,
    ) -> AnalysisResult:
        """Analyze *rules* and return a complete :class:`AnalysisResult`.

        Parameters
        ----------
        rules:
            Normalized firewall rules to analyze.
        vendor:
            Firewall vendor identifier (e.g. ``"paloalto"``, ``"fortigate"``).
        filename:
            Original config file name for the report.
        """
        if not rules:
            logger.info("No rules to analyze for %s (%s)", filename, vendor)
            return AnalysisResult(
                filename=filename,
                vendor=vendor,
                imported_at=datetime.now(),
                rules=[],
            )

        logger.info(
            "Analyzing %d rules from %s (%s)", len(rules), filename, vendor
        )

        shadowed = detect_shadowed_rules(rules)
        conflicts = detect_conflicts(rules)
        redundant = detect_redundant_rules(rules)
        permissive = detect_permissive_rules(rules)

        result = AnalysisResult(
            filename=filename,
            vendor=vendor,
            imported_at=datetime.now(),
            rules=rules,
            shadowed=_sort_findings(shadowed),
            conflicts=_sort_findings(conflicts),
            redundant=_sort_findings(redundant),
            permissive=_sort_findings(permissive),
        )

        logger.info(
            "Analysis complete — %d total findings "
            "(shadow=%d, conflict=%d, redundant=%d, permissive=%d)",
            result.total_issues(),
            len(shadowed),
            len(conflicts),
            len(redundant),
            len(permissive),
        )

        return result
