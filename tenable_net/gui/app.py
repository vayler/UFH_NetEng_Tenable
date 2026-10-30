"""Main window and application entrypoint for the desktop app."""

import sys
import traceback
from datetime import datetime
from pathlib import Path

import pandas as pd
from PySide6.QtCore import QSettings, Qt, QUrl
from PySide6.QtGui import QAction, QActionGroup, QColor, QDesktopServices, QKeySequence, QPalette
from PySide6.QtWidgets import (
    QApplication, QLabel, QMainWindow, QMessageBox, QPushButton, QStackedWidget, QStyle, QTabWidget,
    QVBoxLayout, QWidget,
)

from tenable_net import __version__, export, normalize, reports
from tenable_net.gui.devices import DevicesTab
from tenable_net.gui.dialogs import PullDialog, SettingsDialog
from tenable_net.gui.findings import FindingsTab
from tenable_net.gui.overview import OverviewTab


def dark_palette():
    pal = QPalette()
    colors = {
        QPalette.Window: "#202124", QPalette.WindowText: "#e8eaed", QPalette.Base: "#2a2b2e",
        QPalette.AlternateBase: "#303134", QPalette.ToolTipBase: "#303134", QPalette.ToolTipText: "#e8eaed",
        QPalette.Text: "#e8eaed", QPalette.Button: "#303134", QPalette.ButtonText: "#e8eaed",
        QPalette.BrightText: "#ff5252", QPalette.Highlight: "#3d6fb6", QPalette.HighlightedText: "#ffffff",
        QPalette.Link: "#8ab4f8", QPalette.Mid: "#5f6368", QPalette.PlaceholderText: "#9aa0a6",
    }
    for role, color in colors.items():
        pal.setColor(role, QColor(color))
    pal.setColor(QPalette.Disabled, QPalette.Text, QColor("#80868b"))
    pal.setColor(QPalette.Disabled, QPalette.ButtonText, QColor("#80868b"))
    return pal


def apply_theme(app, theme):
    """theme: 'system', 'light' or 'dark'."""
    app.setStyle("Fusion")
    hints = app.styleHints()
    if hasattr(hints, "setColorScheme"):  # Qt 6.8+: let Qt pick the matching palette
        scheme = {"light": Qt.ColorScheme.Light, "dark": Qt.ColorScheme.Dark}.get(theme, Qt.ColorScheme.Unknown)
        hints.setColorScheme(scheme)
    system_dark = hasattr(hints, "colorScheme") and hints.colorScheme() == Qt.ColorScheme.Dark
    if theme == "dark" or (theme == "system" and system_dark):
        app.setPalette(dark_palette())
    else:
        app.setPalette(app.style().standardPalette())


class MainWindow(QMainWindow):
    def __init__(self, cache_dir=export.DEFAULT_CACHE_DIR):
        super().__init__()
        self.cache_dir = Path(cache_dir)
        self.settings = QSettings("UFH NetEng", "tenable_net")
        self.findings = pd.DataFrame()
        self.assets = pd.DataFrame()
        self.meta = {}
        self.setWindowTitle("Tenable Network Vulnerabilities")
        self.resize(1400, 880)

        self.overview = OverviewTab()
        self.findings_tab = FindingsTab()
        self.devices_tab = DevicesTab()
        self.tabs = QTabWidget(documentMode=True)
        self.tabs.addTab(self.overview, "Overview")
        self.tabs.addTab(self.findings_tab, "Findings")
        self.tabs.addTab(self.devices_tab, "Devices")

        self.overview.device_activated.connect(self.open_device)
        self.overview.plugin_activated.connect(self.open_plugin)
        self.overview.severity_activated.connect(self.open_severity)

        self.stack = QStackedWidget()
        self.stack.addWidget(self._empty_page())
        self.stack.addWidget(self.tabs)
        self.setCentralWidget(self.stack)

        self._build_actions()
        self.status_label = QLabel()
        self.statusBar().addWidget(self.status_label, 1)
        self.findings_tab.count_changed.connect(self._update_status)

        geometry = self.settings.value("geometry")
        if geometry:
            self.restoreGeometry(geometry)
        self.reload()

    # ---- chrome -------------------------------------------------------------
    def _build_actions(self):
        icon = self.style().standardIcon
        self.pull_action = QAction(icon(QStyle.SP_ArrowDown), "Pull from Tenable…", self)
        self.pull_action.setShortcut(QKeySequence("Ctrl+P"))
        self.pull_action.triggered.connect(self.pull)
        self.reload_action = QAction(icon(QStyle.SP_BrowserReload), "Reload cache", self)
        self.reload_action.setShortcut(QKeySequence.Refresh)
        self.reload_action.triggered.connect(self.reload)
        self.report_action = QAction(icon(QStyle.SP_DialogSaveButton), "Export full report", self)
        self.report_action.setShortcut(QKeySequence("Ctrl+E"))
        self.report_action.triggered.connect(self.export_report)
        self.settings_action = QAction(icon(QStyle.SP_FileDialogDetailedView), "API keys…", self)
        self.settings_action.triggered.connect(self.open_settings)
        find_action = QAction("Find", self)
        find_action.setShortcut(QKeySequence.Find)
        find_action.triggered.connect(self.focus_search)
        self.addAction(find_action)

        toolbar = self.addToolBar("Main")
        toolbar.setObjectName("MainToolbar")
        toolbar.setMovable(False)
        toolbar.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        for action in (self.pull_action, self.reload_action, self.report_action, self.settings_action):
            toolbar.addAction(action)

        file_menu = self.menuBar().addMenu("&File")
        for action in (self.pull_action, self.reload_action, self.report_action, self.settings_action):
            file_menu.addAction(action)
        file_menu.addSeparator()
        file_menu.addAction("Quit", QKeySequence.Quit, self.close)

        view_menu = self.menuBar().addMenu("&View")
        theme_menu = view_menu.addMenu("Theme")
        group = QActionGroup(self)
        current = self.settings.value("theme", "system")
        for theme in ("system", "light", "dark"):
            act = QAction(theme.title(), self, checkable=True, checked=theme == current)
            act.triggered.connect(lambda _=False, t=theme: self.set_theme(t))
            group.addAction(act)
            theme_menu.addAction(act)

        help_menu = self.menuBar().addMenu("&Help")
        help_menu.addAction("About", lambda: QMessageBox.about(
            self, "About", f"<b>tenable_net</b> {__version__}<br>Tenable VM explorer for network equipment."))

    def _empty_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addStretch(1)
        title = QLabel("<h2>No data yet</h2>Pull your findings from Tenable to get started.")
        title.setAlignment(Qt.AlignCenter)
        pull = QPushButton("Pull from Tenable…")
        pull.setMinimumHeight(36)
        pull.clicked.connect(self.pull)
        keys = QPushButton("Set API keys…")
        keys.clicked.connect(self.open_settings)
        layout.addWidget(title)
        for b in (pull, keys):
            b.setFixedWidth(240)
            layout.addWidget(b, alignment=Qt.AlignCenter)
        layout.addStretch(2)
        return page

    def set_theme(self, theme):
        self.settings.setValue("theme", theme)
        apply_theme(QApplication.instance(), theme)
        if not self.findings.empty:
            self.overview.set_data(self.findings)  # charts pick up palette colors when built

    # ---- data ---------------------------------------------------------------
    def reload(self):
        try:
            vulns, assets, self.meta = export.load_cache(self.cache_dir)
        except FileNotFoundError:
            self.stack.setCurrentIndex(0)
            self.report_action.setEnabled(False)
            self.status_label.setText(f"No cached data in {self.cache_dir.resolve()}")
            return
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            findings = normalize.findings_frame(vulns, include_info=True)
            findings["vendor"] = findings["os"].map(normalize.vendor_of)
            self.findings = findings
            self.assets = normalize.assets_frame(assets)
            self.overview.set_data(findings)
            self.findings_tab.set_data(findings)
            self.devices_tab.set_data(findings, self.assets)
        finally:
            QApplication.restoreOverrideCursor()
        self.stack.setCurrentIndex(1)
        self.report_action.setEnabled(True)
        self._update_status()

    def _update_status(self, *_):
        pulled = self.meta.get("pulled_at", "unknown")
        try:
            pulled = datetime.fromisoformat(pulled).astimezone().strftime("%Y-%m-%d %H:%M")
        except (TypeError, ValueError):
            pass
        filters = self.meta.get("filters") or {}
        sev = ", ".join(filters.get("severity") or []) or "all"
        state = ", ".join(filters.get("state") or []) or "all"
        since = f" · last {filters['since_days']} days" if filters.get("since_days") else ""
        self.status_label.setText(
            f"Data pulled {pulled} · {len(self.findings):,} findings · "
            f"{self.findings['hostname'].nunique() if not self.findings.empty else 0:,} devices · "
            f"severity: {sev} · state: {state}{since}"
        )

    def pull(self):
        dialog = PullDialog(self.cache_dir, self)
        if dialog.exec() and dialog.meta:
            self.reload()
            self.statusBar().showMessage("Pull complete.", 5000)

    def open_settings(self):
        SettingsDialog(self).exec()

    def export_report(self):
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            paths = reports.write_reports(self.findings.drop(columns=["vendor"]), self.assets)
        finally:
            QApplication.restoreOverrideCursor()
        folder = paths[0].parent.resolve()
        self.statusBar().showMessage(f"Report written to {folder}", 8000)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(folder)))

    # ---- navigation -----------------------------------------------------------
    def open_device(self, hostname):
        self.tabs.setCurrentWidget(self.devices_tab)
        self.devices_tab.select_device(hostname)

    def open_plugin(self, plugin_id):
        self.tabs.setCurrentWidget(self.findings_tab)
        self.findings_tab.show_query(plugin_id)

    def open_severity(self, severity):
        self.tabs.setCurrentWidget(self.findings_tab)
        self.findings_tab.show_query("", severity=severity)

    def focus_search(self):
        if self.tabs.currentWidget() is self.devices_tab:
            self.devices_tab.search.setFocus()
        else:
            self.tabs.setCurrentWidget(self.findings_tab)
            self.findings_tab.search.setFocus()
            self.findings_tab.search.selectAll()

    def closeEvent(self, event):
        self.settings.setValue("geometry", self.saveGeometry())
        super().closeEvent(event)


CRASH_LOG = Path("logs") / "gui-error.log"


def install_crash_handler(log_path=CRASH_LOG):
    """Log uncaught exceptions to a file and show them in a dialog.

    The Windows launcher starts the app with pythonw, which has no console, so without this
    an error would vanish silently.
    """
    def hook(exc_type, exc, tb):
        text = "".join(traceback.format_exception(exc_type, exc, tb))
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with log_path.open("a", encoding="utf-8") as fh:
                fh.write(f"\n=== {datetime.now():%Y-%m-%d %H:%M:%S} ===\n{text}")
        except OSError:
            pass
        if sys.stderr:  # None under pythonw
            sys.__excepthook__(exc_type, exc, tb)
        if QApplication.instance():
            QMessageBox.critical(None, "Unexpected error",
                                 f"{exc_type.__name__}: {exc}\n\nDetails were written to:\n{log_path.resolve()}")

    sys.excepthook = hook
    return hook


def main(cache_dir=export.DEFAULT_CACHE_DIR):
    install_crash_handler()
    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("tenable_net")
    app.setOrganizationName("UFH NetEng")
    apply_theme(app, QSettings("UFH NetEng", "tenable_net").value("theme", "system"))
    window = MainWindow(cache_dir)
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
