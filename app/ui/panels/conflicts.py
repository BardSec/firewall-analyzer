"""Conflicts panel — rules with contradictory actions on overlapping traffic."""

from PySide6.QtWidgets import QScrollArea, QVBoxLayout, QWidget

from app.models import AnalysisResult
from app.ui.panels.base import (
    make_card,
    make_card_row,
    make_empty_state,
    make_section_header,
    make_severity_badge,
    make_table,
)
from app.ui.theme import COLORS


class ConflictsPanel(QScrollArea):
    def __init__(self):
        super().__init__()
        self.setWidgetResizable(True)
        self.setFrameShape(QScrollArea.NoFrame)

    def load(self, result: AnalysisResult):
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        findings = result.conflicts

        if not findings:
            layout.addWidget(make_empty_state("No rule conflicts detected."))
            layout.addStretch()
            self.setWidget(container)
            return

        # ── Summary cards ────────────────────────────────────────
        critical_count = sum(1 for f in findings if f.severity == "CRITICAL")
        high_count = sum(1 for f in findings if f.severity == "HIGH")

        cards = [
            make_card("Total Conflicts", str(len(findings)), COLORS["danger"]),
            make_card("CRITICAL", str(critical_count), COLORS["critical"] if critical_count else COLORS["success"]),
            make_card("HIGH", str(high_count), COLORS["high"] if high_count else COLORS["success"]),
        ]
        layout.addWidget(make_card_row(cards))

        # ── Findings table ───────────────────────────────────────
        layout.addWidget(make_section_header("Rule Conflicts"))

        headers = ["Severity", "Rule A", "Rule B", "Description", "Recommendation"]
        rows = []
        for f in findings:
            rule_a = f.rule_ids[0] if len(f.rule_ids) > 0 else ""
            rule_b = f.rule_ids[1] if len(f.rule_ids) > 1 else ""
            rows.append([f.severity, rule_a, rule_b, f.description, f.recommendation])

        table = make_table(headers, rows)
        for r, f in enumerate(findings):
            badge = make_severity_badge(f.severity)
            table.setCellWidget(r, 0, badge)

        table.setMinimumHeight(min(len(findings) * 40 + 40, 600))
        layout.addWidget(table)

        layout.addStretch()
        self.setWidget(container)
