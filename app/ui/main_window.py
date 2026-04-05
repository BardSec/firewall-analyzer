import os
import sys

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from app.models import AnalysisResult
from app.parsers import auto_detect_vendor, SUPPORTED_VENDORS, PARSERS
from app.analysis.engine import AnalysisEngine
from app.ui.dashboard import Dashboard
from app.ui.theme import COLORS

# Map vendor name -> parser class for manual selection fallback
_VENDOR_PARSER_MAP = {p.vendor_name: p for p in PARSERS}


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Firewall Analyzer")
        self.setMinimumSize(1280, 800)
        self.resize(1440, 900)

        self.configs: list[AnalysisResult] = []

        self._build_ui()

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QHBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        splitter = QSplitter(Qt.Horizontal)

        # ── Sidebar ──────────────────────────────────────────────
        sidebar = QWidget()
        sidebar.setFixedWidth(264)
        sidebar.setStyleSheet(f"background-color: {COLORS['bg_panel']};")
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(0, 0, 0, 0)
        sidebar_layout.setSpacing(0)

        # Logo / title area
        logo_container = QWidget()
        logo_container.setStyleSheet(f"background-color: {COLORS['bg_card']}; padding: 16px;")
        logo_layout = QVBoxLayout(logo_container)
        logo_layout.setContentsMargins(16, 16, 16, 16)

        logo_row = QHBoxLayout()
        logo_icon = QLabel("FW")
        logo_icon.setStyleSheet(
            f"background-color: {COLORS['accent']}; color: white; font-size: 14px; "
            f"font-weight: 800; border-radius: 6px; padding: 4px 8px;"
        )
        logo_icon.setFixedSize(36, 36)
        logo_icon.setAlignment(Qt.AlignCenter)
        logo_row.addWidget(logo_icon)

        title_col = QVBoxLayout()
        title_col.setSpacing(2)
        title_label = QLabel("Firewall Analyzer")
        title_label.setStyleSheet("font-size: 16px; font-weight: 700; color: white;")
        title_col.addWidget(title_label)
        subtitle = QLabel("Config Audit Tool")
        subtitle.setStyleSheet(f"font-size: 11px; color: {COLORS['text_muted']};")
        title_col.addWidget(subtitle)
        logo_row.addLayout(title_col)
        logo_row.addStretch()

        logo_layout.addLayout(logo_row)
        sidebar_layout.addWidget(logo_container)

        # Import button
        import_btn = QPushButton("Import Config")
        import_btn.setStyleSheet(f"""
            QPushButton {{
                margin: 12px;
                padding: 10px;
                background-color: {COLORS['accent']};
                border-radius: 6px;
                font-weight: 600;
            }}
            QPushButton:hover {{ background-color: {COLORS['accent_hover']}; }}
        """)
        import_btn.clicked.connect(self._import_config)
        sidebar_layout.addWidget(import_btn)

        # Config list header
        list_header = QLabel("CONFIGS")
        list_header.setStyleSheet(f"""
            color: {COLORS['text_muted']};
            font-size: 10px;
            font-weight: 700;
            letter-spacing: 1px;
            padding: 12px 12px 6px 12px;
        """)
        sidebar_layout.addWidget(list_header)

        self.config_list = QListWidget()
        self.config_list.currentRowChanged.connect(self._on_config_selected)
        sidebar_layout.addWidget(self.config_list, 1)

        # Footer
        footer = QWidget()
        footer.setStyleSheet(f"background-color: {COLORS['bg_card']}; border-top: 1px solid {COLORS['border']};")
        footer_layout = QVBoxLayout(footer)
        footer_layout.setContentsMargins(12, 10, 12, 10)
        footer_layout.setSpacing(4)
        footer_layout.setAlignment(Qt.AlignCenter)

        link = QLabel(
            f'<a href="https://bardsec.com" style="color: {COLORS["text_muted"]}; '
            f'font-size: 10px; text-decoration: none;">bardsec.com</a>'
        )
        link.setAlignment(Qt.AlignCenter)
        link.setOpenExternalLinks(True)
        link.setStyleSheet("border: none;")
        footer_layout.addWidget(link)

        copyright_label = QLabel("\u00a9 2026 BardSec. All rights reserved.")
        copyright_label.setAlignment(Qt.AlignCenter)
        copyright_label.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 9px; border: none;")
        footer_layout.addWidget(copyright_label)

        sidebar_layout.addWidget(footer)

        splitter.addWidget(sidebar)

        # ── Main content ─────────────────────────────────────────
        self.dashboard = Dashboard()
        splitter.addWidget(self.dashboard)

        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)

        layout.addWidget(splitter)

    # ── Actions ────────────────────────────────────────────────────

    def _import_config(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Import Firewall Config",
            "",
            "Firewall Configs (*.xml *.conf *.cfg *.txt *.json);;All Files (*)",
        )
        if not file_path:
            return

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except Exception as exc:
            QMessageBox.critical(self, "Import Error", f"Could not read file:\n\n{exc}")
            return

        parser = auto_detect_vendor(content)

        if parser is None:
            vendor_name, ok = QInputDialog.getItem(
                self,
                "Select Vendor",
                "Could not detect vendor automatically.\nPlease select the firewall vendor:",
                SUPPORTED_VENDORS,
                0,
                False,
            )
            if not ok or not vendor_name:
                return
            parser_cls = _VENDOR_PARSER_MAP.get(vendor_name)
            if parser_cls is None:
                return
            parser = parser_cls()

        try:
            rules = parser.parse(content)
            vendor_name = parser.vendor_name
            engine = AnalysisEngine()
            result = engine.analyze(rules, vendor_name, os.path.basename(file_path))
        except Exception as exc:
            QMessageBox.critical(self, "Analysis Failed", f"Error analyzing config:\n\n{exc}")
            return

        self.configs.append(result)
        self._update_config_list()
        self.config_list.setCurrentRow(len(self.configs) - 1)

    def _update_config_list(self):
        self.config_list.clear()
        for cfg in self.configs:
            text = f"{cfg.filename} ({cfg.vendor})\n  {len(cfg.rules)} rules"
            item = QListWidgetItem(text)
            self.config_list.addItem(item)

    def _on_config_selected(self, row: int):
        if 0 <= row < len(self.configs):
            self.dashboard.show_results(self.configs[row])

    @staticmethod
    def _resource_path(relative_path: str) -> str:
        """Get absolute path to resource, works for dev and PyInstaller."""
        if getattr(sys, "frozen", False):
            base = sys._MEIPASS
        else:
            base = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        return os.path.join(base, relative_path)
