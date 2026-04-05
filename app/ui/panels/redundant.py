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
from app.ui.panels.overview import FindingDetailDialog
from app.ui.theme import COLORS


class RedundantPanel(QScrollArea):
    def __init__(self):
        super().__init__()
        self.setWidgetResizable(True)
        self.setFrameShape(QScrollArea.NoFrame)
        self._result = None
        self._findings = []

    def load(self, result: AnalysisResult):
        self._result = result
        self._findings = result.redundant
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        if not self._findings:
            layout.addWidget(make_empty_state("No redundant rules detected."))
            layout.addStretch()
            self.setWidget(container)
            return

        cards = [
            make_card("Total Redundant", str(len(self._findings)), COLORS["warning"]),
        ]
        layout.addWidget(make_card_row(cards))

        layout.addWidget(make_section_header("Redundant Rules  (click a row for details)"))

        headers = ["Severity", "Rule", "Redundant With", "Description"]
        rows = []
        for f in self._findings:
            rule = f.rule_ids[0] if len(f.rule_ids) > 0 else ""
            redundant_with = f.rule_ids[1] if len(f.rule_ids) > 1 else ""
            rows.append([f.severity, rule, redundant_with, f.title])

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
