"""What-If Analysis panel — clone rules, edit, re-analyze, and diff."""

import copy

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.models import AnalysisResult, FirewallRule
from app.analysis.engine import AnalysisEngine
from app.ui.panels.base import make_card, make_card_row, make_section_header, make_table
from app.ui.theme import COLORS

_RULE_HEADERS = ["#", "Name", "Action", "Src Zone", "Dst Zone", "Src Addr", "Dst Addr", "Services", "Enabled", "Log"]


class WhatIfPanel(QScrollArea):
    def __init__(self):
        super().__init__()
        self.setWidgetResizable(True)
        self.setFrameShape(QScrollArea.NoFrame)

        self._original_result: AnalysisResult | None = None
        self._cloned_rules: list[FirewallRule] | None = None
        self._edit_table: QTableWidget | None = None
        self._diff_container: QWidget | None = None

    def load(self, result: AnalysisResult):
        self._original_result = result
        self._cloned_rules = None
        self._edit_table = None
        self._diff_container = None

        container = QWidget()
        self._layout = QVBoxLayout(container)
        self._layout.setContentsMargins(16, 16, 16, 16)
        self._layout.setSpacing(12)

        # ── Start button ─────────────────────────────────────────
        self._start_btn = QPushButton("Start What-If Analysis")
        self._start_btn.setStyleSheet(f"""
            QPushButton {{
                padding: 10px 24px;
                background-color: {COLORS['accent']};
                border-radius: 6px;
                font-weight: 600;
                font-size: 13px;
            }}
            QPushButton:hover {{ background-color: {COLORS['accent_hover']}; }}
        """)
        self._start_btn.clicked.connect(self._start_whatif)
        self._layout.addWidget(self._start_btn, 0, Qt.AlignLeft)

        # Placeholder for the edit area (filled on clone)
        self._edit_area = QWidget()
        self._edit_layout = QVBoxLayout(self._edit_area)
        self._edit_layout.setContentsMargins(0, 0, 0, 0)
        self._edit_layout.setSpacing(12)
        self._edit_area.hide()
        self._layout.addWidget(self._edit_area, 1)

        self._layout.addStretch()
        self.setWidget(container)

    # ── Clone & build editable table ─────────────────────────────

    def _start_whatif(self):
        if self._original_result is None:
            return

        self._cloned_rules = copy.deepcopy(self._original_result.rules)
        self._start_btn.hide()
        self._edit_area.show()

        # Clear previous edit layout contents
        while self._edit_layout.count():
            item = self._edit_layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

        self._edit_layout.addWidget(make_section_header("Edit Rules"))

        # Toolbar
        toolbar = QWidget()
        tb_layout = QHBoxLayout(toolbar)
        tb_layout.setContentsMargins(0, 0, 0, 0)
        tb_layout.setSpacing(8)

        add_btn = QPushButton("Add Rule")
        add_btn.setProperty("class", "outline")
        add_btn.clicked.connect(self._add_rule)
        tb_layout.addWidget(add_btn)

        del_btn = QPushButton("Delete Selected")
        del_btn.setProperty("class", "danger")
        del_btn.clicked.connect(self._delete_selected)
        tb_layout.addWidget(del_btn)

        up_btn = QPushButton("Move Up")
        up_btn.setProperty("class", "outline")
        up_btn.clicked.connect(self._move_up)
        tb_layout.addWidget(up_btn)

        down_btn = QPushButton("Move Down")
        down_btn.setProperty("class", "outline")
        down_btn.clicked.connect(self._move_down)
        tb_layout.addWidget(down_btn)

        toggle_btn = QPushButton("Toggle Enable")
        toggle_btn.setProperty("class", "outline")
        toggle_btn.clicked.connect(self._toggle_enable)
        tb_layout.addWidget(toggle_btn)

        tb_layout.addStretch()
        self._edit_layout.addWidget(toolbar)

        # Editable table
        self._build_edit_table()
        self._edit_layout.addWidget(self._edit_table, 1)

        # Analyze button
        analyze_btn = QPushButton("Analyze Changes")
        analyze_btn.setStyleSheet(f"""
            QPushButton {{
                padding: 10px 24px;
                background-color: {COLORS['accent']};
                border-radius: 6px;
                font-weight: 600;
            }}
            QPushButton:hover {{ background-color: {COLORS['accent_hover']}; }}
        """)
        analyze_btn.clicked.connect(self._analyze_changes)
        self._edit_layout.addWidget(analyze_btn, 0, Qt.AlignLeft)

        # Diff results area
        self._diff_container = QWidget()
        self._diff_layout = QVBoxLayout(self._diff_container)
        self._diff_layout.setContentsMargins(0, 0, 0, 0)
        self._diff_layout.setSpacing(12)
        self._diff_container.hide()
        self._edit_layout.addWidget(self._diff_container)

    def _build_edit_table(self):
        rules = self._cloned_rules
        self._edit_table = QTableWidget(len(rules), len(_RULE_HEADERS))
        self._edit_table.setHorizontalHeaderLabels(_RULE_HEADERS)
        self._edit_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self._edit_table.verticalHeader().setVisible(False)
        self._edit_table.setSelectionBehavior(QTableWidget.SelectRows)

        for r, rule in enumerate(rules):
            self._populate_row(r, rule)

    def _populate_row(self, r: int, rule: FirewallRule):
        values = [
            str(rule.position),
            rule.name,
            rule.action,
            ", ".join(rule.src_zones),
            ", ".join(rule.dst_zones),
            ", ".join(rule.src_addrs),
            ", ".join(rule.dst_addrs),
            ", ".join(rule.services),
            "Yes" if rule.enabled else "No",
            "Yes" if rule.logging else "No",
        ]
        for c, val in enumerate(values):
            item = QTableWidgetItem(val)
            item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
            self._edit_table.setItem(r, c, item)

    # ── Toolbar actions ──────────────────────────────────────────

    def _add_rule(self):
        if self._cloned_rules is None or self._edit_table is None:
            return
        new_pos = len(self._cloned_rules) + 1
        new_rule = FirewallRule(
            id=f"new-{new_pos}",
            name=f"New Rule {new_pos}",
            enabled=True,
            action="deny",
            src_zones=["any"],
            dst_zones=["any"],
            src_addrs=["any"],
            dst_addrs=["any"],
            services=["any"],
            logging=False,
            position=new_pos,
        )
        self._cloned_rules.append(new_rule)
        row = self._edit_table.rowCount()
        self._edit_table.insertRow(row)
        self._populate_row(row, new_rule)

    def _delete_selected(self):
        if self._edit_table is None or self._cloned_rules is None:
            return
        rows = sorted({idx.row() for idx in self._edit_table.selectedIndexes()}, reverse=True)
        for row in rows:
            if 0 <= row < len(self._cloned_rules):
                self._cloned_rules.pop(row)
                self._edit_table.removeRow(row)

    def _move_up(self):
        if self._edit_table is None or self._cloned_rules is None:
            return
        row = self._edit_table.currentRow()
        if row <= 0:
            return
        self._cloned_rules[row], self._cloned_rules[row - 1] = (
            self._cloned_rules[row - 1],
            self._cloned_rules[row],
        )
        self._populate_row(row, self._cloned_rules[row])
        self._populate_row(row - 1, self._cloned_rules[row - 1])
        self._edit_table.setCurrentCell(row - 1, 0)

    def _move_down(self):
        if self._edit_table is None or self._cloned_rules is None:
            return
        row = self._edit_table.currentRow()
        if row < 0 or row >= len(self._cloned_rules) - 1:
            return
        self._cloned_rules[row], self._cloned_rules[row + 1] = (
            self._cloned_rules[row + 1],
            self._cloned_rules[row],
        )
        self._populate_row(row, self._cloned_rules[row])
        self._populate_row(row + 1, self._cloned_rules[row + 1])
        self._edit_table.setCurrentCell(row + 1, 0)

    def _toggle_enable(self):
        if self._edit_table is None or self._cloned_rules is None:
            return
        rows = sorted({idx.row() for idx in self._edit_table.selectedIndexes()})
        for row in rows:
            if 0 <= row < len(self._cloned_rules):
                self._cloned_rules[row].enabled = not self._cloned_rules[row].enabled
                self._populate_row(row, self._cloned_rules[row])

    # ── Analyze & Diff ───────────────────────────────────────────

    def _rebuild_rules_from_table(self) -> list[FirewallRule]:
        """Read the editable table back into FirewallRule objects."""
        rules = []
        for r in range(self._edit_table.rowCount()):
            def _cell(c: int) -> str:
                item = self._edit_table.item(r, c)
                return item.text() if item else ""

            def _split(c: int) -> list[str]:
                raw = _cell(c)
                return [s.strip() for s in raw.split(",") if s.strip()] or ["any"]

            rule = FirewallRule(
                id=f"whatif-{r}",
                name=_cell(1),
                enabled=_cell(8).lower() in ("yes", "true", "1"),
                action=_cell(2).lower() or "deny",
                src_zones=_split(3),
                dst_zones=_split(4),
                src_addrs=_split(5),
                dst_addrs=_split(6),
                services=_split(7),
                logging=_cell(9).lower() in ("yes", "true", "1"),
                position=r + 1,
            )
            rules.append(rule)
        return rules

    def _analyze_changes(self):
        if self._original_result is None or self._edit_table is None:
            return

        modified_rules = self._rebuild_rules_from_table()

        try:
            engine = AnalysisEngine()
            modified_result = engine.analyze(
                modified_rules,
                self._original_result.vendor,
                self._original_result.filename,
            )
        except Exception as exc:
            QMessageBox.critical(self.widget(), "Analysis Failed", f"Error:\n\n{exc}")
            return

        # Diff findings
        original_set = {(f.finding_type, f.severity, f.description) for f in self._original_result.all_findings()}
        modified_set = {(f.finding_type, f.severity, f.description) for f in modified_result.all_findings()}

        resolved = original_set - modified_set
        new_issues = modified_set - original_set

        # Rebuild diff display
        self._diff_container.show()
        while self._diff_layout.count():
            item = self._diff_layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

        # Summary card
        summary_cards = [
            make_card("Resolved", str(len(resolved)), COLORS["success"]),
            make_card("New Issues", str(len(new_issues)), COLORS["danger"] if new_issues else COLORS["success"]),
        ]
        self._diff_layout.addWidget(make_card_row(summary_cards))

        # Resolved issues
        if resolved:
            self._diff_layout.addWidget(make_section_header("Issues Resolved"))
            headers = ["Type", "Severity", "Description"]
            rows = [[t, s, d] for t, s, d in sorted(resolved)]
            table = make_table(headers, rows, sortable=False)
            table.setMinimumHeight(min(len(rows) * 36 + 40, 300))
            # Green tint
            for r in range(table.rowCount()):
                for c in range(table.columnCount()):
                    item = table.item(r, c)
                    if item:
                        item.setForeground(QColor(COLORS["success"]))
            self._diff_layout.addWidget(table)

        # New issues
        if new_issues:
            self._diff_layout.addWidget(make_section_header("New Issues"))
            headers = ["Type", "Severity", "Description"]
            rows = [[t, s, d] for t, s, d in sorted(new_issues)]
            table = make_table(headers, rows, sortable=False)
            table.setMinimumHeight(min(len(rows) * 36 + 40, 300))
            for r in range(table.rowCount()):
                for c in range(table.columnCount()):
                    item = table.item(r, c)
                    if item:
                        item.setForeground(QColor(COLORS["danger"]))
            self._diff_layout.addWidget(table)

        if not resolved and not new_issues:
            lbl = QLabel("No differences found.")
            lbl.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 14px; padding: 16px;")
            lbl.setAlignment(Qt.AlignCenter)
            self._diff_layout.addWidget(lbl)
