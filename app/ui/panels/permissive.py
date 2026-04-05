"""Overly Permissive panel — rules that are too broad or use 'any'."""

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


class PermissivePanel(QScrollArea):
    def __init__(self):
        super().__init__()
        self.setWidgetResizable(True)
        self.setFrameShape(QScrollArea.NoFrame)

    def load(self, result: AnalysisResult):
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        findings = result.permissive

        if not findings:
            layout.addWidget(make_empty_state("No overly permissive rules detected."))
            layout.addStretch()
            self.setWidget(container)
            return

        # ── Summary cards ────────────────────────────────────────
        critical = sum(1 for f in findings if f.severity == "CRITICAL")
        high = sum(1 for f in findings if f.severity == "HIGH")
        medium = sum(1 for f in findings if f.severity == "MEDIUM")
        low = sum(1 for f in findings if f.severity == "LOW")

        cards = [
            make_card("Total", str(len(findings)), COLORS["warning"]),
            make_card("CRITICAL", str(critical), COLORS["critical"] if critical else COLORS["success"]),
            make_card("HIGH", str(high), COLORS["high"] if high else COLORS["success"]),
            make_card("MEDIUM", str(medium), COLORS["medium"] if medium else COLORS["success"]),
            make_card("LOW", str(low), COLORS["low"] if low else COLORS["success"]),
        ]
        layout.addWidget(make_card_row(cards))

        # ── Findings table ───────────────────────────────────────
        layout.addWidget(make_section_header("Overly Permissive Rules"))

        headers = ["Severity", "Rule", "Issue", "Recommendation"]
        rows = []
        for f in findings:
            rule = ", ".join(f.rule_ids) if f.rule_ids else ""
            rows.append([f.severity, rule, f.description, f.recommendation])

        table = make_table(headers, rows)
        for r, f in enumerate(findings):
            badge = make_severity_badge(f.severity)
            table.setCellWidget(r, 0, badge)

        table.setMinimumHeight(min(len(findings) * 40 + 40, 600))
        layout.addWidget(table)

        layout.addStretch()
        self.setWidget(container)
