"""Shadowed Rules panel — rules hidden by higher-priority rules."""

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


class ShadowedPanel(QScrollArea):
    def __init__(self):
        super().__init__()
        self.setWidgetResizable(True)
        self.setFrameShape(QScrollArea.NoFrame)

    def load(self, result: AnalysisResult):
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        findings = result.shadowed

        if not findings:
            layout.addWidget(make_empty_state("No shadowed rules detected."))
            layout.addStretch()
            self.setWidget(container)
            return

        # ── Summary cards ────────────────────────────────────────
        high_count = sum(1 for f in findings if f.severity == "HIGH")
        medium_count = sum(1 for f in findings if f.severity == "MEDIUM")

        cards = [
            make_card("Total Shadowed", str(len(findings)), COLORS["danger"]),
            make_card("HIGH", str(high_count), COLORS["high"] if high_count else COLORS["success"]),
            make_card("MEDIUM", str(medium_count), COLORS["medium"] if medium_count else COLORS["success"]),
        ]
        layout.addWidget(make_card_row(cards))

        # ── Findings table ───────────────────────────────────────
        layout.addWidget(make_section_header("Shadowed Rules"))

        headers = ["Severity", "Shadowed Rule", "Shadowed By", "Description", "Recommendation"]
        rows = []
        for f in findings:
            shadowed_rule = f.rule_ids[0] if len(f.rule_ids) > 0 else ""
            shadowed_by = f.rule_ids[1] if len(f.rule_ids) > 1 else ""
            rows.append([f.severity, shadowed_rule, shadowed_by, f.description, f.recommendation])

        table = make_table(headers, rows)
        for r, f in enumerate(findings):
            badge = make_severity_badge(f.severity)
            table.setCellWidget(r, 0, badge)

        table.setMinimumHeight(min(len(findings) * 40 + 40, 600))
        layout.addWidget(table)

        layout.addStretch()
        self.setWidget(container)
