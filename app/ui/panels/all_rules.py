"""All Rules panel — searchable table of every firewall rule."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QHeaderView,
    QLineEdit,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.models import AnalysisResult
from app.ui.theme import COLORS

_HEADERS = ["#", "Name", "Action", "Src Zone", "Dst Zone", "Src Addr", "Dst Addr", "Services", "Enabled", "Log"]

_ACTION_COLORS = {
    "allow": COLORS["success"],
    "deny": COLORS["danger"],
    "drop": COLORS["danger"],
}


class AllRulesPanel(QScrollArea):
    def __init__(self):
        super().__init__()
        self.setWidgetResizable(True)
        self.setFrameShape(QScrollArea.NoFrame)
        self._table: QTableWidget | None = None

    def load(self, result: AnalysisResult):
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Search bar
        self._search = QLineEdit()
        self._search.setPlaceholderText("Filter rules...")
        self._search.setStyleSheet(f"""
            QLineEdit {{
                background-color: {COLORS['bg_input']};
                border: 1px solid {COLORS['border']};
                border-radius: 6px;
                padding: 8px 12px;
                color: {COLORS['text']};
                font-size: 13px;
            }}
            QLineEdit:focus {{
                border-color: {COLORS['accent']};
            }}
        """)
        self._search.textChanged.connect(self._on_filter)
        layout.addWidget(self._search)

        # Table
        rules = result.rules
        self._table = QTableWidget(len(rules), len(_HEADERS))
        self._table.setHorizontalHeaderLabels(_HEADERS)
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self._table.verticalHeader().setVisible(False)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.setSortingEnabled(True)

        for r, rule in enumerate(rules):
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

                # Color the action column
                if c == 2:
                    color = _ACTION_COLORS.get(rule.action.lower(), COLORS["text"])
                    item.setForeground(Qt.GlobalColor.white)  # reset first
                    from PySide6.QtGui import QColor
                    item.setForeground(QColor(color))

                # Muted text for disabled rules
                if not rule.enabled:
                    from PySide6.QtGui import QColor
                    item.setForeground(QColor(COLORS["text_muted"]))

                self._table.setItem(r, c, item)

        layout.addWidget(self._table, 1)

        layout.addStretch()
        self.setWidget(container)

    def _on_filter(self, text: str):
        if self._table is None:
            return
        text = text.lower()
        for row in range(self._table.rowCount()):
            match = False
            if not text:
                match = True
            else:
                for col in range(self._table.columnCount()):
                    item = self._table.item(row, col)
                    if item and text in item.text().lower():
                        match = True
                        break
            self._table.setRowHidden(row, not match)
