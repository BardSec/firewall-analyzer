"""Overview panel — summary cards, top issues, and rule distribution."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QScrollArea, QTableWidgetItem, QVBoxLayout, QWidget

from app.models import AnalysisResult
from app.ui.panels.base import (
    make_card,
    make_card_row,
    make_section_header,
    make_severity_badge,
    make_table,
)
from app.ui.theme import COLORS

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


class OverviewPanel(QScrollArea):
    def __init__(self):
        super().__init__()
        self.setWidgetResizable(True)
        self.setFrameShape(QScrollArea.NoFrame)

    def load(self, result: AnalysisResult):
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # ── Summary cards ────────────────────────────────────────
        layout.addWidget(make_section_header("Summary"))

        def _color(count: int, danger_threshold: bool = True) -> str:
            if count == 0:
                return COLORS["success"]
            return COLORS["danger"] if danger_threshold else COLORS["warning"]

        cards = [
            make_card("Total Rules", str(len(result.rules))),
            make_card("Shadowed", str(len(result.shadowed)), _color(len(result.shadowed))),
            make_card("Conflicts", str(len(result.conflicts)), _color(len(result.conflicts))),
            make_card("Redundant", str(len(result.redundant)), _color(len(result.redundant), False)),
            make_card("Overly Permissive", str(len(result.permissive)), _color(len(result.permissive), False)),
        ]
        layout.addWidget(make_card_row(cards))

        # ── Top Issues ───────────────────────────────────────────
        all_findings = result.all_findings()
        if all_findings:
            layout.addWidget(make_section_header("Top Issues"))

            sorted_findings = sorted(all_findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))
            top = sorted_findings[:10]

            headers = ["Severity", "Type", "Description", "Rules"]
            rows = []
            for f in top:
                rows.append([f.severity, f.finding_type, f.description, ", ".join(f.rule_ids)])

            table = make_table(headers, rows)

            # Replace severity text cells with badges
            for r, f in enumerate(top):
                badge = make_severity_badge(f.severity)
                table.setCellWidget(r, 0, badge)

            table.setMinimumHeight(min(len(top) * 40 + 40, 460))
            layout.addWidget(table)

        # ── Rule Distribution ────────────────────────────────────
        layout.addWidget(make_section_header("Rule Distribution"))

        allow_count = sum(1 for r in result.rules if r.action == "allow")
        deny_count = sum(1 for r in result.rules if r.action == "deny")
        drop_count = sum(1 for r in result.rules if r.action == "drop")
        disabled_count = sum(1 for r in result.rules if not r.enabled)

        dist_cards = [
            make_card("Allow", str(allow_count), COLORS["success"]),
            make_card("Deny", str(deny_count), COLORS["danger"]),
            make_card("Drop", str(drop_count), COLORS["warning"]),
            make_card("Disabled", str(disabled_count), COLORS["text_muted"]),
        ]
        layout.addWidget(make_card_row(dist_cards))

        layout.addStretch()
        self.setWidget(container)
