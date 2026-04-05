"""Overview panel — summary cards, top issues, and rule distribution."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.models import AnalysisResult, Finding, FirewallRule
from app.ui.panels.base import (
    make_card,
    make_card_row,
    make_section_header,
    make_severity_badge,
    make_table,
)
from app.ui.theme import COLORS

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


class FindingDetailDialog(QDialog):
    """Modal dialog showing finding details, referenced rules, and recommendations."""

    def __init__(self, finding: Finding, rules: list[FirewallRule], parent=None):
        super().__init__(parent)
        self.setWindowTitle("Finding Detail")
        self.setMinimumSize(700, 500)
        self.setStyleSheet(f"background-color: {COLORS['bg_dark']}; color: {COLORS['text']};")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)

        # Severity + type header
        header = QWidget()
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.addWidget(make_severity_badge(finding.severity))
        type_label = QLabel(finding.finding_type.upper())
        type_label.setStyleSheet(f"font-size: 12px; font-weight: 700; color: {COLORS['text_muted']};")
        header_layout.addWidget(type_label)
        header_layout.addStretch()
        layout.addWidget(header)

        # Title
        title = QLabel(finding.title)
        title.setWordWrap(True)
        title.setStyleSheet(f"font-size: 16px; font-weight: 700; color: {COLORS['text']};")
        layout.addWidget(title)

        # Description
        desc = QLabel(finding.description)
        desc.setWordWrap(True)
        desc.setStyleSheet(f"font-size: 13px; color: {COLORS['text']};")
        layout.addWidget(desc)

        # Referenced rules
        rule_map = {r.id: r for r in rules}
        referenced = [rule_map[rid] for rid in finding.rule_ids if rid in rule_map]

        if referenced:
            layout.addWidget(make_section_header("Referenced Rules"))
            for rule in referenced:
                layout.addWidget(self._make_rule_card(rule))

        # Recommendation
        if finding.recommendation:
            layout.addWidget(make_section_header("Recommendation"))
            rec = QLabel(finding.recommendation)
            rec.setWordWrap(True)
            rec.setStyleSheet(
                f"font-size: 13px; color: {COLORS['text']}; "
                f"background-color: {COLORS['accent']}15; "
                f"border: 1px solid {COLORS['accent']}33; "
                f"border-radius: 6px; padding: 12px;"
            )
            layout.addWidget(rec)

        layout.addStretch()

    def _make_rule_card(self, rule: FirewallRule) -> QWidget:
        card = QWidget()
        card.setStyleSheet(
            f"background-color: {COLORS['bg_card']}; "
            f"border: 1px solid {COLORS['border']}; border-radius: 6px;"
        )
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(14, 10, 14, 10)
        card_layout.setSpacing(6)

        # Rule name + position
        name_row = QWidget()
        name_layout = QHBoxLayout(name_row)
        name_layout.setContentsMargins(0, 0, 0, 0)

        pos_label = QLabel(f"#{rule.position}")
        pos_label.setStyleSheet(
            f"font-size: 11px; font-weight: 700; color: {COLORS['text_muted']}; "
            f"background-color: {COLORS['bg_input']}; border-radius: 3px; padding: 2px 6px;"
        )
        name_layout.addWidget(pos_label)

        rule_name = QLabel(rule.name)
        rule_name.setStyleSheet(f"font-size: 14px; font-weight: 700; color: {COLORS['text']}; border: none;")
        name_layout.addWidget(rule_name)

        action_color = COLORS["success"] if rule.action == "allow" else COLORS["danger"]
        action_label = QLabel(rule.action.upper())
        action_label.setStyleSheet(
            f"font-size: 10px; font-weight: 700; color: {action_color}; "
            f"background-color: {action_color}22; border: 1px solid {action_color}44; "
            f"border-radius: 3px; padding: 2px 8px;"
        )
        name_layout.addWidget(action_label)

        if not rule.enabled:
            dis_label = QLabel("DISABLED")
            dis_label.setStyleSheet(
                f"font-size: 10px; font-weight: 700; color: {COLORS['text_muted']}; "
                f"background-color: {COLORS['bg_input']}; border-radius: 3px; padding: 2px 8px;"
            )
            name_layout.addWidget(dis_label)

        name_layout.addStretch()
        card_layout.addWidget(name_row)

        # Rule details grid
        details = [
            ("Source Zones", ", ".join(rule.src_zones)),
            ("Dest Zones", ", ".join(rule.dst_zones)),
            ("Source Addresses", ", ".join(rule.src_addrs)),
            ("Dest Addresses", ", ".join(rule.dst_addrs)),
            ("Services", ", ".join(rule.services)),
            ("Logging", "Yes" if rule.logging else "No"),
        ]

        for label_text, value_text in details:
            row = QWidget()
            row_layout = QHBoxLayout(row)
            row_layout.setContentsMargins(0, 0, 0, 0)
            row_layout.setSpacing(8)

            label = QLabel(label_text)
            label.setFixedWidth(130)
            label.setStyleSheet(f"font-size: 11px; color: {COLORS['text_muted']}; border: none;")
            row_layout.addWidget(label)

            value = QLabel(value_text)
            value.setWordWrap(True)
            log_color = COLORS["danger"] if label_text == "Logging" and value_text == "No" else COLORS["text"]
            value.setStyleSheet(f"font-size: 12px; color: {log_color}; border: none;")
            row_layout.addWidget(value, 1)

            card_layout.addWidget(row)

        return card


class OverviewPanel(QScrollArea):
    def __init__(self):
        super().__init__()
        self.setWidgetResizable(True)
        self.setFrameShape(QScrollArea.NoFrame)
        self._result: AnalysisResult | None = None
        self._top_findings: list[Finding] = []

    def load(self, result: AnalysisResult):
        self._result = result
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

        # ── Top Issues (clickable) ───────────────────────────────
        all_findings = result.all_findings()
        if all_findings:
            layout.addWidget(make_section_header("Top Issues  (click a row for details)"))

            sorted_findings = sorted(all_findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))
            self._top_findings = sorted_findings[:10]

            headers = ["Severity", "Type", "Description", "Rules"]
            rows = []
            for f in self._top_findings:
                rows.append([f.severity, f.finding_type, f.title, ", ".join(f.rule_ids)])

            table = make_table(headers, rows)
            table.setSelectionBehavior(table.SelectionBehavior.SelectRows)
            table.setSelectionMode(table.SelectionMode.SingleSelection)
            table.cellDoubleClicked.connect(self._on_finding_clicked)
            # Also single-click
            table.cellClicked.connect(self._on_finding_clicked)

            # Replace severity text cells with badges
            for r, f in enumerate(self._top_findings):
                badge = make_severity_badge(f.severity)
                table.setCellWidget(r, 0, badge)

            table.setMinimumHeight(min(len(self._top_findings) * 40 + 40, 460))
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

    def _on_finding_clicked(self, row: int, _col: int):
        if not self._result or row >= len(self._top_findings):
            return
        finding = self._top_findings[row]
        dialog = FindingDetailDialog(finding, self._result.rules, parent=self)
        dialog.exec()
