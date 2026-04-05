import json

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QSplitter,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from app.models import AnalysisResult
from app.ui.panels.overview import OverviewPanel
from app.ui.panels.all_rules import AllRulesPanel
from app.ui.panels.shadowed import ShadowedPanel
from app.ui.panels.conflicts import ConflictsPanel
from app.ui.panels.redundant import RedundantPanel
from app.ui.panels.permissive import PermissivePanel
from app.ui.panels.whatif import WhatIfPanel
from app.ui.theme import COLORS


# (display_label, finding_attr_or_None, PanelClass)
NAV_ITEMS = [
    ("Overview", None, OverviewPanel),
    ("All Rules", None, AllRulesPanel),
    ("Shadowed Rules", "shadowed", ShadowedPanel),
    ("Conflicts", "conflicts", ConflictsPanel),
    ("Redundant Rules", "redundant", RedundantPanel),
    ("Overly Permissive", "permissive", PermissivePanel),
    ("What If", None, WhatIfPanel),
]


class Dashboard(QWidget):
    def __init__(self):
        super().__init__()
        self._result: AnalysisResult | None = None
        self._nav_to_stack: dict[int, int] = {}
        self._build_ui()

    def _build_ui(self):
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(0)

        # ── Welcome screen ───────────────────────────────────────
        self.welcome = QWidget()
        welcome_layout = QVBoxLayout(self.welcome)
        welcome_layout.setAlignment(Qt.AlignCenter)

        title = QLabel("Import a firewall config to begin")
        title.setStyleSheet(f"font-size: 20px; color: {COLORS['text_muted']}; font-weight: 600;")
        title.setAlignment(Qt.AlignCenter)
        welcome_layout.addWidget(title)

        subtitle = QLabel("Supports Palo Alto, Fortinet, Cisco ASA, pfSense, and more")
        subtitle.setStyleSheet(f"font-size: 13px; color: {COLORS['text_muted']};")
        subtitle.setAlignment(Qt.AlignCenter)
        welcome_layout.addWidget(subtitle)

        # ── Dashboard ────────────────────────────────────────────
        self.dashboard_widget = QWidget()
        self.dashboard_layout = QVBoxLayout(self.dashboard_widget)
        self.dashboard_layout.setContentsMargins(16, 16, 16, 16)
        self.dashboard_layout.setSpacing(12)

        # Header bar
        self.header = QWidget()
        header_layout = QHBoxLayout(self.header)
        header_layout.setContentsMargins(0, 0, 0, 0)

        self.filename_label = QLabel("")
        self.filename_label.setStyleSheet(f"font-size: 18px; font-weight: 700; color: {COLORS['text']};")
        header_layout.addWidget(self.filename_label)

        self.vendor_badge = QLabel("")
        self.vendor_badge.setStyleSheet(
            f"background-color: {COLORS['accent']}22; color: {COLORS['accent']}; "
            f"border: 1px solid {COLORS['accent']}44; border-radius: 4px; "
            f"padding: 2px 10px; font-size: 11px; font-weight: 700;"
        )
        header_layout.addWidget(self.vendor_badge)

        self.meta_label = QLabel("")
        self.meta_label.setStyleSheet(f"font-size: 12px; color: {COLORS['text_muted']};")
        header_layout.addWidget(self.meta_label)

        header_layout.addStretch()

        self.export_btn = QPushButton("Export JSON")
        self.export_btn.setProperty("class", "outline")
        self.export_btn.clicked.connect(self._export_json)
        header_layout.addWidget(self.export_btn)

        self.dashboard_layout.addWidget(self.header)

        # Content area: nav list + panel stack
        content_splitter = QSplitter(Qt.Horizontal)
        content_splitter.setHandleWidth(1)

        self.nav_list = QListWidget()
        self.nav_list.setFixedWidth(210)
        self.nav_list.setStyleSheet(f"""
            QListWidget {{
                background-color: {COLORS['bg_panel']};
                border: none;
                border-right: 1px solid {COLORS['border']};
                border-top: 1px solid {COLORS['border']};
                border-top-left-radius: 6px;
                outline: none;
                font-size: 13px;
            }}
            QListWidget::item {{
                padding: 7px 12px 7px 16px;
                border: none;
                border-bottom: none;
            }}
            QListWidget::item:selected {{
                background-color: {COLORS['accent']}18;
                color: {COLORS['accent']};
                border-left: 3px solid {COLORS['accent']};
                padding-left: 13px;
            }}
            QListWidget::item:hover:!selected {{
                background-color: {COLORS['bg_card']};
            }}
        """)
        self.nav_list.currentRowChanged.connect(self._on_nav_changed)

        self.panel_stack = QStackedWidget()
        self.panel_stack.setStyleSheet(f"""
            QStackedWidget {{
                border: 1px solid {COLORS['border']};
                border-left: none;
                border-top-right-radius: 6px;
                border-bottom-right-radius: 6px;
                background-color: {COLORS['bg_panel']};
            }}
        """)

        content_splitter.addWidget(self.nav_list)
        content_splitter.addWidget(self.panel_stack)
        content_splitter.setStretchFactor(0, 0)
        content_splitter.setStretchFactor(1, 1)

        self.dashboard_layout.addWidget(content_splitter, 1)

        # Top-level stack (welcome vs dashboard)
        self.stack = QStackedWidget()
        self.stack.addWidget(self.welcome)
        self.stack.addWidget(self.dashboard_widget)
        self.layout.addWidget(self.stack)

    # ── Public ────────────────────────────────────────────────────

    def show_results(self, result: AnalysisResult):
        self._result = result

        # Update header
        self.filename_label.setText(result.filename)
        self.vendor_badge.setText(result.vendor)
        ts = result.imported_at.strftime("%Y-%m-%d %H:%M") if result.imported_at else ""
        self.meta_label.setText(f"{len(result.rules)} rules  \u2022  {ts}")

        # Clear previous panels
        self.nav_list.clear()
        while self.panel_stack.count():
            w = self.panel_stack.widget(0)
            self.panel_stack.removeWidget(w)
            w.deleteLater()
        self._nav_to_stack.clear()

        # Build panels
        for stack_idx, (label, attr, panel_cls) in enumerate(NAV_ITEMS):
            panel = panel_cls()
            panel.load(result)
            self.panel_stack.addWidget(panel)

        # Build nav list
        self._build_nav_list(result)

        # Select overview
        self.nav_list.setCurrentRow(0)
        self.stack.setCurrentIndex(1)

    # ── Private ───────────────────────────────────────────────────

    def _build_nav_list(self, result: AnalysisResult):
        for nav_row, (label, attr, _panel_cls) in enumerate(NAV_ITEMS):
            if attr is not None:
                count = result.finding_count(attr)
                display = f"{label} ({count})" if count > 0 else label
            else:
                display = label

            item = QListWidgetItem(display)
            if nav_row == 0:  # Overview is bold
                bold_font = QFont()
                bold_font.setBold(True)
                item.setFont(bold_font)

            self.nav_list.addItem(item)
            self._nav_to_stack[nav_row] = nav_row

    def _on_nav_changed(self, row: int):
        if row in self._nav_to_stack:
            self.panel_stack.setCurrentIndex(self._nav_to_stack[row])

    def _export_json(self):
        if not self._result:
            return

        base_name = self._result.filename.rsplit(".", 1)[0]
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Analysis Results",
            f"{base_name}_analysis.json",
            "JSON Files (*.json)",
        )
        if not file_path:
            return

        with open(file_path, "w") as f:
            json.dump(self._result.to_export_dict(), f, indent=2, default=str)
