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
from app.ui.panels.overview import FindingDetailDialog
from app.ui.theme import COLORS


class ShadowedPanel(QScrollArea):
    def __init__(self):
        super().__init__()
        self.setWidgetResizable(True)
        self.setFrameShape(QScrollArea.NoFrame)
        self._result = None
        self._findings = []

    def load(self, result: AnalysisResult):
        self._result = result
        self._findings = result.shadowed
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        if not self._findings:
            layout.addWidget(make_empty_state("No shadowed rules detected."))
            layout.addStretch()
            self.setWidget(container)
            return

        # Summary cards
        high_count = sum(1 for f in self._findings if f.severity == "HIGH")
        medium_count = sum(1 for f in self._findings if f.severity == "MEDIUM")

        cards = [
            make_card("Total Shadowed", str(len(self._findings)), COLORS["danger"]),
            make_card("HIGH", str(high_count), COLORS["high"] if high_count else COLORS["success"]),
            make_card("MEDIUM", str(medium_count), COLORS["medium"] if medium_count else COLORS["success"]),
        ]
        layout.addWidget(make_card_row(cards))

        # Findings table
        layout.addWidget(make_section_header("Shadowed Rules  (click a row for details)"))

        headers = ["Severity", "Shadowed Rule", "Shadowed By", "Description"]
        rows = []
        for f in self._findings:
            shadowed_rule = f.rule_ids[0] if len(f.rule_ids) > 0 else ""
            shadowed_by = f.rule_ids[1] if len(f.rule_ids) > 1 else ""
            rows.append([f.severity, shadowed_rule, shadowed_by, f.title])

        table = make_table(headers, rows)
        table.cellClicked.connect(self._on_row_clicked)
        for r, f in enumerate(self._findings):
            badge = make_severity_badge(f.severity)
            table.setCellWidget(r, 0, badge)

        table.setMinimumHeight(min(len(self._findings) * 40 + 40, 600))
        layout.addWidget(table)

        layout.addStretch()
        self.setWidget(container)

    def _on_row_clicked(self, row, _col):
        if not self._result or row >= len(self._findings):
            return
        dialog = FindingDetailDialog(self._findings[row], self._result.rules, parent=self)
        dialog.exec()
