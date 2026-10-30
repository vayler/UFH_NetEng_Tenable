"""Main window and application entrypoint for the desktop app.

Layout: a UF Health header (title, data freshness, source status, global search, primary actions),
a navigation sidebar and one page per view. All jumps between views go through navigate().
"""

import html
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
from PySide6.QtCore import QFileSystemWatcher, QSettings, QSize, QStringListModel, Qt, QTimer, QUrl
from PySide6.QtGui import QAction, QActionGroup, QDesktopServices, QKeySequence
from PySide6.QtWidgets import (
    QApplication, QCompleter, QDialog, QFrame, QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem,
    QMainWindow, QMessageBox, QPushButton, QStackedWidget, QTextBrowser, QVBoxLayout, QWidget,
)

from tenable_net import __version__, akips, cisco, client, export, glossary, inventory, normalize, reports
from tenable_net.gui import theme
from tenable_net.gui.devices import DevicesTab
from tenable_net.gui.dialogs import PullDialog, SettingsDialog
from tenable_net.gui.findings import FindingsTab
from tenable_net.gui.overview import OverviewTab
from tenable_net.gui.widgets import Chip, Toast

APP_TITLE = "UF Health · Network Vulnerability Explorer"

# (key, sidebar label, page title, page subtitle). Pages are created in MainWindow._build_pages.
NAV = [
    ("overview", "Overview", "Overview", "Where the network stands right now"),
    ("findings", "Findings", "Findings", "Every vulnerability Tenable reports, with filters and details"),
    ("devices", "Devices", "Devices", "Risk, hardware and findings per device"),
    ("diagnostics", "Diagnostics", "Enrichment diagnostics", "Why devices are missing hardware or Cisco data"),
]
NAV_INFO = {key: (title, subtitle) for key, _label, title, subtitle in NAV}


def apply_theme(app, mode_name):
    """Kept for callers of the old API; see theme.apply."""
    return theme.apply(app, mode_name)


def _ago(iso):
    try:
        then = datetime.fromisoformat(iso)
    except (TypeError, ValueError):
        return None, None
    hours = (datetime.now(timezone.utc) - then.astimezone(timezone.utc)).total_seconds() / 3600
    if hours < 1:
        text = f"{max(int(hours * 60), 0)} min ago"
    elif hours < 48:
        text = f"{int(hours)} h ago"
    else:
        text = f"{int(hours // 24)} days ago"
    return text, hours


class GlossaryDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Glossary")
        self.resize(640, 620)
        view = QTextBrowser()
        view.setHtml("".join(f"<h4 style='margin-bottom:2px'>{html.escape(k)}</h4><p style='margin-top:0'>"
                             f"{html.escape(v)}</p>" for k, v in glossary.TERMS.items()))
        QVBoxLayout(self).addWidget(view)


class MainWindow(QMainWindow):
    def __init__(self, cache_dir=export.DEFAULT_CACHE_DIR):
        super().__init__()
        self.cache_dir = Path(cache_dir)
        self.settings = QSettings("UFH NetEng", "tenable_net")
        self.findings = pd.DataFrame()
        self.assets = pd.DataFrame()
        self.inventory = pd.DataFrame()
        self.meta = {}
        self.diagnostics_window = None
        self._cache_signature = None
        self.setWindowTitle(APP_TITLE)
        self.resize(1440, 900)

        self.toast = None
        self._build_pages()
        sidebar = self._build_sidebar()
        topbar = self._build_header()
        self.stack = QStackedWidget()  # 0 = getting started (no data), 1 = pages
        self.stack.addWidget(self._empty_page())
        content_page = QWidget()
        content_layout = QVBoxLayout(content_page)
        content_layout.setContentsMargins(20, 16, 20, 12)
        content_layout.addWidget(self.pages)
        self.stack.addWidget(content_page)
        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)
        right_layout.addWidget(topbar)
        right_layout.addWidget(self.stack, 1)
        central = QWidget()
        outer = QHBoxLayout(central)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        outer.addWidget(sidebar)
        outer.addWidget(right, 1)
        self.setCentralWidget(central)
        self.nav.setCurrentRow(0)
        self._page_changed(0)

        self._build_actions()
        self.status_label = QLabel()
        self.statusBar().addWidget(self.status_label, 1)
        self.findings_tab.count_changed.connect(self._update_status)
        self.toast = Toast(self)

        self._fresh_timer = QTimer(self, interval=60_000)
        self._fresh_timer.timeout.connect(self._update_header)
        self._fresh_timer.start()
        self._watch_timer = QTimer(self, singleShot=True, interval=1500)
        self._watch_timer.timeout.connect(self._cache_changed)
        self.watcher = QFileSystemWatcher(self)
        self.watcher.fileChanged.connect(lambda _p: self._watch_timer.start())
        self.watcher.directoryChanged.connect(lambda _p: self._watch_timer.start())

        geometry = self.settings.value("geometry")
        if geometry:
            self.restoreGeometry(geometry)
        self.reload()

    # ---- layout -----------------------------------------------------------------
    def _build_pages(self):
        self.overview = OverviewTab()
        self.findings_tab = FindingsTab()
        self.devices_tab = DevicesTab()
        self.overview.device_activated.connect(lambda h: self.navigate("devices", hostname=h))
        self.overview.plugin_activated.connect(lambda p: self.navigate("findings", text=p))
        self.overview.severity_activated.connect(lambda s: self.navigate("findings", severity=s))
        self.pages = QStackedWidget()
        self.views = {"overview": self.overview, "findings": self.findings_tab, "devices": self.devices_tab}
        self.view_keys = []
        for key, *_rest in NAV:
            page = self.views.get(key) or QWidget()  # lazily-built views start as placeholders
            self.views[key] = page
            self.pages.addWidget(page)
            self.view_keys.append(key)
        self.tabs = self.pages  # older name, still used by scripts

    def _build_header(self):
        """White top bar over the content: page title, status indicators, search and actions."""
        bar = QFrame()
        bar.setObjectName("TopBar")
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(20, 10, 20, 10)
        layout.setSpacing(10)
        titles = QVBoxLayout()
        titles.setSpacing(0)
        self.page_title = QLabel()
        self.page_title.setObjectName("PageTitle")
        self.page_title.setFont(theme.font("title", bold=True))
        self.page_subtitle = QLabel()
        self.page_subtitle.setObjectName("PageSubtitle")

        titles.addWidget(self.page_title)
        titles.addWidget(self.page_subtitle)
        layout.addLayout(titles)
        layout.addStretch(1)

        self.global_search = QLineEdit(placeholderText="Search devices, CVEs, plugins…   Ctrl+K")
        self.global_search.setMinimumWidth(200)
        self.global_search.setMaximumWidth(320)
        self.global_search.setClearButtonEnabled(True)
        self.global_search.setFocusPolicy(Qt.ClickFocus)  # don't grab focus at start-up; Ctrl+K focuses it
        self.search_model = QStringListModel(self)
        completer = QCompleter(self.search_model, self)
        completer.setCaseSensitivity(Qt.CaseInsensitive)
        completer.setFilterMode(Qt.MatchContains)
        completer.setMaxVisibleItems(15)
        completer.activated.connect(self._search_activated)
        self.global_search.setCompleter(completer)
        self.global_search.returnPressed.connect(lambda: self._search_activated(self.global_search.text()))
        self.search_targets = {}
        layout.addWidget(self.global_search)

        self.report_button = QPushButton("Export report")
        self.report_button.clicked.connect(self.export_report)
        pull = QPushButton("Pull from Tenable")
        pull.setObjectName("Primary")
        pull.clicked.connect(self.pull)
        layout.addWidget(self.report_button)
        layout.addWidget(pull)
        return bar

    def _build_sidebar(self):
        """Navy sidebar: UF Health brand block, navigation, settings and version."""
        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(224)
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(0, 18, 0, 12)
        layout.setSpacing(0)
        brand = QLabel("UF Health")
        brand.setObjectName("BrandName")
        brand.setFont(theme.font("brand", bold=True))
        product = QLabel("Network Vulnerability Explorer")
        product.setFont(theme.font("caption"))
        for widget in (brand, product):
            widget.setContentsMargins(20, 0, 12, 0)
        layout.addWidget(brand)
        layout.addWidget(product)
        layout.addSpacing(10)
        accent = QFrame()
        accent.setObjectName("BrandAccent")
        accent.setFixedSize(28, 3)
        accent_row = QHBoxLayout()
        accent_row.setContentsMargins(20, 0, 0, 0)
        accent_row.addWidget(accent)
        accent_row.addStretch(1)
        layout.addLayout(accent_row)
        layout.addSpacing(22)
        caption = QLabel("VIEWS")
        caption.setObjectName("SidebarCaption")
        caption.setFont(theme.font("caption", bold=True))
        caption.setContentsMargins(26, 0, 0, 6)
        layout.addWidget(caption)

        self.nav = QListWidget()
        self.nav.setObjectName("Nav")
        self.nav.setFocusPolicy(Qt.NoFocus)
        for key, label, *_rest in NAV:
            item = QListWidgetItem(label)
            item.setData(Qt.UserRole, key)
            item.setSizeHint(QSize(0, 38))
            self.nav.addItem(item)
        self.nav.currentRowChanged.connect(self._nav_changed)
        self.pages.currentChanged.connect(self._page_changed)
        self.nav.setFixedHeight(len(NAV) * 40 + 8)
        layout.addWidget(self.nav)
        layout.addStretch(1)

        # data freshness + source status: quiet dot + label rows; click for details
        sources = QLabel("DATA SOURCES")
        sources.setObjectName("SidebarCaption")
        sources.setFont(theme.font("caption", bold=True))
        sources.setContentsMargins(26, 0, 0, 4)
        layout.addWidget(sources)
        self.fresh_chip = Chip("No data")
        self.fresh_chip.clicked.connect(self.pull)
        self.source_chips = {name: Chip(name) for name in ("Tenable", "AKiPS", "Cisco")}
        self.source_chips["Tenable"].clicked.connect(self.open_settings)
        self.source_chips["AKiPS"].clicked.connect(lambda: self.navigate("diagnostics"))
        self.source_chips["Cisco"].clicked.connect(lambda: self.navigate("diagnostics"))
        for chip in (self.fresh_chip, *self.source_chips.values()):
            chip.setObjectName("SidebarStatus")
            chip.setCursor(Qt.PointingHandCursor)
            layout.addWidget(chip)
        layout.addSpacing(12)

        settings = QListWidget()
        settings.setObjectName("Nav")
        settings.setFocusPolicy(Qt.NoFocus)
        settings_item = QListWidgetItem("Settings")
        settings_item.setSizeHint(QSize(0, 38))
        settings.addItem(settings_item)
        settings.setFixedHeight(46)
        settings.itemClicked.connect(lambda _item: (settings.clearSelection(), self.open_settings()))
        layout.addWidget(settings)
        version = QLabel(f"Network Engineering · v{__version__}")
        version.setObjectName("SidebarVersion")
        version.setFont(theme.font("caption"))
        version.setContentsMargins(26, 8, 0, 0)
        layout.addWidget(version)
        return sidebar

    def _empty_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addStretch(1)
        card = QFrame()
        card.setObjectName("Card")
        card.setMaximumWidth(560)
        inner = QVBoxLayout(card)
        inner.setContentsMargins(28, 24, 28, 24)
        title = QLabel("Getting started")
        title.setFont(theme.font("headline", bold=True))
        self.checklist = QLabel()
        self.checklist.setTextFormat(Qt.RichText)
        self.checklist.setWordWrap(True)
        pull = QPushButton("Pull from Tenable…")
        pull.setObjectName("Primary")
        pull.setMinimumHeight(34)
        pull.clicked.connect(self.pull)
        keys = QPushButton("Settings (API keys)…")
        keys.clicked.connect(self.open_settings)
        inner.addWidget(title)
        inner.addWidget(self.checklist)
        buttons = QHBoxLayout()
        buttons.addWidget(pull)
        buttons.addWidget(keys)
        inner.addLayout(buttons)
        layout.addWidget(card, alignment=Qt.AlignCenter)
        layout.addStretch(2)
        return page

    def _build_actions(self):
        self.pull_action = QAction("Pull from Tenable…", self, shortcut=QKeySequence("Ctrl+P"))
        self.pull_action.triggered.connect(self.pull)
        self.reload_action = QAction("Reload cache", self, shortcut=QKeySequence.Refresh)
        self.reload_action.triggered.connect(self.reload)
        self.report_action = QAction("Export full report", self, shortcut=QKeySequence("Ctrl+E"))
        self.report_action.triggered.connect(self.export_report)
        self.settings_action = QAction("Settings…", self)
        self.settings_action.triggered.connect(self.open_settings)
        for text, keys, slot in (("Find", QKeySequence.Find, self.focus_search),
                                 ("Search everything", QKeySequence("Ctrl+K"), self.focus_global_search)):
            act = QAction(text, self, shortcut=keys)
            act.triggered.connect(slot)
            self.addAction(act)

        file_menu = self.menuBar().addMenu("&File")
        for action in (self.pull_action, self.reload_action, self.report_action, self.settings_action):
            file_menu.addAction(action)
        file_menu.addSeparator()
        file_menu.addAction("Quit", QKeySequence.Quit, self.close)

        view_menu = self.menuBar().addMenu("&View")
        for i, (key, label, *_rest) in enumerate(NAV, start=1):
            act = QAction(label, self, shortcut=QKeySequence(f"Ctrl+{i}"))
            act.triggered.connect(lambda _=False, k=key: self.navigate(k))
            view_menu.addAction(act)
        view_menu.addSeparator()
        theme_menu = view_menu.addMenu("Theme")
        group = QActionGroup(self)
        current = self.settings.value("theme", "system")
        for name in ("system", "light", "dark"):
            act = QAction(name.title(), self, checkable=True, checked=name == current)
            act.triggered.connect(lambda _=False, t=name: self.set_theme(t))
            group.addAction(act)
            theme_menu.addAction(act)

        tools_menu = self.menuBar().addMenu("&Tools")
        self.diagnostics_action = tools_menu.addAction("Enrichment diagnostics", self.open_diagnostics)
        self.diagnostics_action.setToolTip("Why devices are missing hardware / Cisco data")

        help_menu = self.menuBar().addMenu("&Help")
        help_menu.addAction("Glossary", lambda: GlossaryDialog(self).exec())
        help_menu.addAction("About", lambda: QMessageBox.about(
            self, "About", f"<b>{APP_TITLE}</b><br>tenable_net {__version__}<br>"
                           "Tenable vulnerability explorer for UF Health network equipment."))

    # ---- navigation -------------------------------------------------------------
    def _nav_changed(self, row):
        item = self.nav.item(row)
        if item is not None:
            self.show_view(item.data(Qt.UserRole))

    def _page_changed(self, index):
        self.nav.blockSignals(True)
        self.nav.setCurrentRow(index)
        self.nav.blockSignals(False)
        title, subtitle = NAV_INFO[self.view_keys[index]]
        self.page_title.setText(title)
        self.page_subtitle.setText(subtitle)

    def current_view(self):
        return self.view_keys[self.pages.currentIndex()]

    def show_view(self, key):
        page = self._ensure_view(key)
        if self.pages.currentWidget() is not page:
            self.pages.setCurrentWidget(page)
        return page

    def _ensure_view(self, key):
        """Build lazily-created views on first use."""
        page = self.views[key]
        if key == "diagnostics" and self.diagnostics_window is None:
            from tenable_net.gui.diagnostics_window import DiagnosticsWindow

            self.diagnostics_window = DiagnosticsWindow(self.cache_dir, self, embedded=True)
            self._replace_page(key, self.diagnostics_window)
            page = self.diagnostics_window
        elif key == "diagnostics":
            self.diagnostics_window.reload()
        return page

    def _replace_page(self, key, widget):
        index = self.view_keys.index(key)
        old = self.pages.widget(index)
        self.pages.blockSignals(True)
        self.pages.insertWidget(index, widget)
        self.pages.removeWidget(old)
        self.pages.blockSignals(False)
        old.deleteLater()
        self.views[key] = widget

    def navigate(self, view, **filters):
        """Show a view, optionally filtered: findings(text=, severity=), devices(hostname=),
        diagnostics(stage=)."""
        page = self.show_view(view)
        if view == "findings" and (filters.get("text") is not None or filters.get("severity")):
            page.show_query(filters.get("text") or "", severity=filters.get("severity"))
        elif view == "devices" and filters.get("hostname"):
            page.select_device(filters["hostname"])
        elif view == "diagnostics" and filters.get("stage"):
            page.select_stage(filters["stage"])
        return page

    # older entry points
    def open_device(self, hostname):
        self.navigate("devices", hostname=hostname)

    def open_plugin(self, plugin_id):
        self.navigate("findings", text=str(plugin_id))

    def open_severity(self, severity):
        self.navigate("findings", severity=severity)

    def open_diagnostics(self):
        return self.navigate("diagnostics")

    def focus_search(self):
        if self.current_view() == "devices":
            self.devices_tab.search.setFocus()
        else:
            self.navigate("findings")
            self.findings_tab.search.setFocus()
            self.findings_tab.search.selectAll()

    def focus_global_search(self):
        self.global_search.setFocus()
        self.global_search.selectAll()

    # ---- global search ------------------------------------------------------------
    def _build_search_index(self):
        targets = {}
        f = self.findings
        if not f.empty:
            for host in f["hostname"].dropna().unique():
                targets[f"Device · {host}"] = ("devices", {"hostname": host})
            for cve in sorted({c for cves in f["cves"].dropna() for c in str(cves).split(", ") if c}):
                targets[f"CVE · {cve}"] = ("findings", {"text": cve})
            plugins = f.drop_duplicates("plugin_id")[["plugin_id", "plugin_name"]]
            for pid, name in plugins.itertuples(index=False):
                targets[f"Plugin · {pid} · {name}"] = ("findings", {"text": str(pid)})
        if not self.assets.empty:
            for host in self.assets["hostname"].dropna().unique():
                targets.setdefault(f"Device · {host}", ("devices", {"hostname": host}))
        if not self.inventory.empty:
            for model in self.inventory["model"].dropna().unique():
                if model:
                    targets[f"Model · {model}"] = ("devices", {"search": model})
            for host, serial in self.inventory[["hostname", "serial"]].itertuples(index=False):
                if serial:
                    targets[f"Serial · {serial} · {host}"] = ("devices", {"hostname": host})
        self.search_targets = targets
        self.search_model.setStringList(sorted(targets))

    def _search_activated(self, text):
        text = (text or "").strip()
        if not text:
            return
        target = self.search_targets.get(text)
        if target is None:  # free text: search findings
            self.navigate("findings", text=text)
        else:
            view, kwargs = target
            if "search" in kwargs:
                page = self.navigate(view)
                page.search.setText(kwargs["search"])
            else:
                self.navigate(view, **kwargs)
        QTimer.singleShot(0, self.global_search.clear)

    # ---- theme ---------------------------------------------------------------------
    def set_theme(self, mode_name):
        self.settings.setValue("theme", mode_name)
        theme.apply(QApplication.instance(), mode_name)
        self._update_header()
        if not self.findings.empty:
            self.overview.set_data(self.findings, self.inventory)  # charts pick up theme colours when built

    # ---- data ---------------------------------------------------------------------
    def _watch_paths(self):
        names = [export.META_FILE, inventory.AKIPS_FILE, inventory.TENABLE_FILE, cisco.CACHE_FILE]
        return [str(self.cache_dir / n) for n in names if (self.cache_dir / n).exists()]

    def _signature(self):
        return tuple((p, Path(p).stat().st_mtime_ns) for p in self._watch_paths())

    def _rewatch(self):
        current = set(self.watcher.files()) | set(self.watcher.directories())
        wanted = set(self._watch_paths())
        if self.cache_dir.exists():
            wanted.add(str(self.cache_dir))
        if wanted - current:
            self.watcher.addPaths(sorted(wanted - current))

    def _cache_changed(self):
        """Another process (e.g. the CLI) updated the cache: reload once it settles."""
        self._rewatch()
        if self._signature() != self._cache_signature:
            self.reload()
            self.notify("Data updated from the cache folder.")

    def reload(self):
        self._rewatch()
        self._cache_signature = self._signature()
        self._update_checklist()
        try:
            vulns, assets, self.meta = export.load_cache(self.cache_dir)
        except FileNotFoundError:
            self.stack.setCurrentIndex(0)
            self.report_action.setEnabled(False)
            self.report_button.setEnabled(False)
            self.status_label.setText(f"No cached data in {self.cache_dir.resolve()}")
            self._update_header()
            return
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            findings = normalize.findings_frame(vulns, include_info=True)
            findings["vendor"] = findings["os"].map(normalize.vendor_of)
            self.findings = findings
            self.assets = normalize.assets_frame(assets)
            self.inventory = inventory.load_inventory(self.cache_dir, vulns, assets)
            self.overview.set_data(findings, self.inventory)
            self.findings_tab.set_data(findings)
            self.devices_tab.set_data(findings, self.assets, self.inventory, self._enrichment_status(vulns, assets))
            if self.diagnostics_window is not None:
                self.diagnostics_window.reload()
            self._build_search_index()
        finally:
            QApplication.restoreOverrideCursor()
        self.stack.setCurrentIndex(1)
        self.report_action.setEnabled(True)
        self.report_button.setEnabled(True)
        self._update_status()
        self._update_header()

    def _enrichment_status(self, vulns, assets):
        """{hostname: (stage, reason)} from the diagnostics report, for the Devices tab header."""
        if self.inventory.empty:
            return {}
        try:
            from tenable_net import diagnostics

            _funnel, devices, _unmatched = diagnostics.enrichment_report(self.cache_dir, vulns, assets)
        except Exception:  # noqa: BLE001 - diagnostics must never stop the app loading
            return {}
        return {r["hostname"]: (r["stage"], r["reason"]) for _, r in devices.iterrows()}

    def _update_header(self):
        text, hours = _ago(self.meta.get("pulled_at"))
        if text is None:
            self.fresh_chip.set("No data yet", "bad", "No data pulled yet. Click to pull from Tenable.")
        else:
            status = "good" if hours < 24 else ("warn" if hours < 24 * 7 else "bad")
            self.fresh_chip.set(f"Pulled {text}", status,
                                f"Last pull: {self.meta.get('pulled_at')}. Amber after 24 h, red after 7 days. "
                                "Click to pull again.")
        access, secret = client.saved_credentials()
        self.source_chips["Tenable"].set("Tenable", "good" if access and secret else "bad",
                                         "Tenable API keys saved" if access and secret else
                                         "No Tenable API keys: click to open Settings")
        if akips.configured():
            rows, _ = inventory._read(self.cache_dir, inventory.AKIPS_FILE)
            self.source_chips["AKiPS"].set("AKiPS", "good" if rows else "warn",
                                           f"{len(rows):,} chassis from AKiPS" if rows else
                                           "Configured; no inventory pulled yet")
        else:
            self.source_chips["AKiPS"].set("AKiPS", "neutral", "AKiPS not configured (optional)")
        if cisco.configured():
            run = cisco.load_cache(self.cache_dir).get("last_run") or {}
            status = "bad" if run.get("errors") else ("good" if run else "warn")
            tip = ("Last Cisco run had errors: " + "; ".join(run.get("errors"))[:300] if run.get("errors") else
                   f"Last Cisco lookup {run.get('at')}" if run else "Configured; no lookups yet")
            self.source_chips["Cisco"].set("Cisco", status, tip + ". Click for diagnostics.")
        else:
            self.source_chips["Cisco"].set("Cisco", "neutral", "Cisco APIs not configured (optional)")

    def _update_checklist(self):
        access, secret = client.saved_credentials()
        steps = [
            ("Save your Tenable API keys (Settings)", bool(access and secret)),
            ("Pull findings from Tenable", (self.cache_dir / export.VULNS_FILE).exists()),
            ("Optional: connect AKiPS for hardware models and serials", akips.configured()),
            ("Optional: connect Cisco APIs for contracts and software suggestions", cisco.configured()),
        ]
        t = theme.tokens()
        self.checklist.setText("<p>Pull your findings from Tenable to get started.</p>" + "".join(
            f"<p style='margin:4px 0'><b style='color:{t['good'] if done else t['text_muted']}'>"
            f"{'✓' if done else '○'}</b>&nbsp; {html.escape(label)}</p>" for label, done in steps))

    def _update_status(self, *_):
        filters = self.meta.get("filters") or {}
        sev = ", ".join(filters.get("severity") or []) or "all"
        state = ", ".join(filters.get("state") or []) or "all"
        since = f" · last {filters['since_days']} days" if filters.get("since_days") else ""
        self.status_label.setText(
            f"{len(self.findings):,} findings · "
            f"{self.findings['hostname'].nunique() if not self.findings.empty else 0:,} devices · "
            f"severity: {sev} · state: {state}{since}"
            + (f" · {len(self.inventory):,} chassis inventoried" if not self.inventory.empty else "")
        )

    def notify(self, text, ms=6000):
        if self.toast is not None:
            self.toast.show_message(text, ms)

    def pull(self):
        dialog = PullDialog(self.cache_dir, self)
        if dialog.exec() and dialog.meta:
            self.reload()
            self.notify(f"Pull finished: {dialog.meta['vuln_count']:,} findings, "
                        f"{dialog.meta['asset_count']:,} assets.")

    def open_settings(self):
        SettingsDialog(self, cache_dir=self.cache_dir).exec()
        self._update_header()
        self._update_checklist()

    def export_report(self):
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            paths = reports.write_reports(self.findings.drop(columns=["vendor"]), self.assets,
                                          inventory=self.inventory)
        finally:
            QApplication.restoreOverrideCursor()
        folder = paths[0].parent.resolve()
        self.notify(f"Report written to {folder}")
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(folder)))

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if self.toast is not None and self.toast.isVisible():
            self.toast.show_message(self.toast.text())

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
    theme.apply(app, QSettings("UFH NetEng", "tenable_net").value("theme", "system"))
    window = MainWindow(cache_dir)
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
