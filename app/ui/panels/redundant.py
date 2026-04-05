"""Redundant Rules panel — rules that duplicate the effect of other rules."""

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


class RedundantPanel(QScrollArea):
    def __init__(self):
        super().__init__()
        self.setWidgetResizable(True)
        self.setFrameShape(QScrollArea.NoFrame)

    def load(self, result: AnalysisResult):
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        findings = result.redundant

        if not findings:
            layout.addWidget(make_empty_state("No redundant rules detected."))
            layout.addStretch()
            self.setWidget(container)
            return

        # ── Summary cards ────────────────────────────────────────
        cards = [
            make_card("Total Redundant", str(len(findings)), COLORS["warning"]),
        ]
        layout.addWidget(make_card_row(cards))

        # ── Findings table ───────────────────────────────────────
        layout.addWidget(make_section_header("Redundant Rules"))

        headers = ["Severity", "Rule", "Redundant With", "Description", "Recommendation"]
        rows = []
        for f in findings:
            rule = f.rule_ids[0] if len(f.rule_ids) > 0 else ""
            redundant_with = f.rule_ids[1] if len(f.rule_ids) > 1 else ""
            rows.append([f.severity, rule, redundant_with, f.description, f.recommendation])

        table = make_table(headers, rows)
        for r, f in enumerate(findings):
            badge = make_severity_badge(f.severity)
            table.setCellWidget(r, 0, badge)

        table.setMinimumHeight(min(len(findings) * 40 + 40, 600))
        layout.addWidget(table)

        layout.addStretch()
        self.setWidget(container)
