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
from app.ui.panels.overview import FindingDetailDialog
from app.ui.theme import COLORS


class ConflictsPanel(QScrollArea):
    def __init__(self):
        super().__init__()
        self.setWidgetResizable(True)
        self.setFrameShape(QScrollArea.NoFrame)
        self._result = None
        self._findings = []

    def load(self, result: AnalysisResult):
        self._result = result
        self._findings = result.conflicts
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        if not self._findings:
            layout.addWidget(make_empty_state("No rule conflicts detected."))
            layout.addStretch()
            self.setWidget(container)
            return

        critical_count = sum(1 for f in self._findings if f.severity == "CRITICAL")
        high_count = sum(1 for f in self._findings if f.severity == "HIGH")

        cards = [
            make_card("Total Conflicts", str(len(self._findings)), COLORS["danger"]),
            make_card("CRITICAL", str(critical_count), COLORS["critical"] if critical_count else COLORS["success"]),
            make_card("HIGH", str(high_count), COLORS["high"] if high_count else COLORS["success"]),
        ]
        layout.addWidget(make_card_row(cards))

        layout.addWidget(make_section_header("Rule Conflicts  (click a row for details)"))

        headers = ["Severity", "Rule A", "Rule B", "Description"]
        rows = []
        for f in self._findings:
            rule_a = f.rule_ids[0] if len(f.rule_ids) > 0 else ""
            rule_b = f.rule_ids[1] if len(f.rule_ids) > 1 else ""
            rows.append([f.severity, rule_a, rule_b, f.title])

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
