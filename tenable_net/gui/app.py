"""Main window and application entrypoint for the desktop app.

Layout: a quiet sidebar (workspace menu, search, navigation with counts, data-source status, settings)
beside an inset content panel with a slim header (page title, Export, Present, Pull). Every command is
also in the command palette (Ctrl+K) and the workspace menu. All jumps between views go through navigate().
"""

import html
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
from PySide6.QtCore import QFileSystemWatcher, QRectF, QSettings, QSize, Qt, QTimer, QUrl
from PySide6.QtGui import QAction, QActionGroup, QColor, QDesktopServices, QKeySequence, QPainter
from PySide6.QtWidgets import (
    QApplication, QDialog, QFileDialog, QFrame, QGridLayout, QHBoxLayout, QLabel, QListWidget, QListWidgetItem,
    QMainWindow, QMenu, QMessageBox, QPushButton, QStyle, QStyledItemDelegate, QTextBrowser,
    QVBoxLayout, QWidget,
)

from tenable_net import (
    __version__, akips, cisco, client, export, glossary, history, inventory, normalize, remediation, reports, risk,
)
from tenable_net.gui import icons, theme
from tenable_net.gui.devices import DevicesTab
from tenable_net.gui.dialogs import PullDialog, SettingsDialog
from tenable_net.gui.findings import FindingsTab
from tenable_net.gui.overview import OverviewTab
from tenable_net.gui.palette import CommandPalette, Entry, shortcut_keys
from tenable_net.gui.widgets import (
    Chip, Kbd, MenuButton, PageStack, SearchField, Toast, button, detail_css, elided, label,
)

APP_TITLE = "UF Health · Network Vulnerability Explorer"
WORKSPACE = "UF Health"
SIDEBAR_WIDTH = 236  # widened in presentation mode for the larger type

# (key, sidebar label, page title, page subtitle, icon). Pages are created in MainWindow._build_pages.
NAV = [
    ("overview", "Overview", "Overview", "Where the network stands right now", "overview"),
    ("findings", "Findings", "Findings", "Every vulnerability Tenable reports, with filters and details", "findings"),
    ("devices", "Devices", "Devices", "Risk, hardware and findings per device", "devices"),
    ("remediation", "Remediation", "Remediation plan", "Fixes ranked by how much risk they remove", "remediation"),
    ("hardware", "Hardware", "Hardware & contracts",
     "Models, serials, software and Cisco contract status for every chassis", "hardware"),
    ("trends", "Trends", "Trends", "How exposure is changing from pull to pull", "trends"),
    ("diagnostics", "Diagnostics", "Enrichment diagnostics", "Why devices are missing hardware or Cisco data",
     "diagnostics"),
]
NAV_INFO = {key: (title, subtitle, icon) for key, _label, title, subtitle, icon in NAV}
NAV_SECTIONS = {"diagnostics": "Tools"}  # a caption above these items
PRESENT_VIEWS = ("overview", "trends", "remediation", "hardware")

COUNT_ROLE = Qt.UserRole + 10
ICON_ROLE = Qt.UserRole + 11
HEADER_ROLE = Qt.UserRole + 12

SHORTCUTS = [
    (("Ctrl", "K"), "Command palette: run a command or jump to a device, CVE or plugin"),
    (("Ctrl", "F"), "Search the current view"),
    (("Ctrl", "1 … 7"), "Go to a view"),
    (("Ctrl", "P"), "Pull from Tenable"),
    (("F5",), "Reload the cache"),
    (("Ctrl", "E"), "Export the Excel report"),
    (("Ctrl", "Shift", "E"), "Executive summary (PDF)"),
    (("Ctrl", "Shift", "S"), "Save the current view as an image"),
    (("F11",), "Presentation mode (Esc leaves)"),
    (("Ctrl", ","), "Settings"),
    (("Ctrl", "/"), "Keyboard shortcuts"),
]


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


# ---- sidebar pieces ------------------------------------------------------------------------------

class NavDelegate(QStyledItemDelegate):
    """Sidebar rows: rounded hover / selected background, icon, label, muted count; captions for sections."""

    def sizeHint(self, option, index):
        h = option.fontMetrics.height()
        return QSize(option.rect.width(), h + (20 if index.data(HEADER_ROLE) else 14))

    def paint(self, painter, option, index):
        t = theme.tokens()
        r = QRectF(option.rect)
        painter.save()
        painter.setRenderHint(QPainter.Antialiasing)
        if index.data(HEADER_ROLE):
            painter.setFont(theme.font("caption", weight="medium"))
            painter.setPen(QColor(t["text_muted"]))
            painter.drawText(r.adjusted(10, 0, -10, -4), Qt.AlignLeft | Qt.AlignBottom, index.data(Qt.DisplayRole))
            painter.restore()
            return
        selected = bool(option.state & QStyle.State_Selected)
        hover = bool(option.state & QStyle.State_MouseOver)
        if selected or hover:
            painter.setPen(Qt.NoPen)
            painter.setBrush(QColor(t["active" if selected else "hover"]))
            painter.drawRoundedRect(r.adjusted(0, 1, 0, -1), 6, 6)
        strong = selected or hover
        size = round(option.fontMetrics.height() * 0.95)
        icons.paint(painter, index.data(ICON_ROLE) or "arrow-right",
                    QRectF(r.left() + 10, r.center().y() - size / 2, size, size),
                    t["text"] if selected else t["text_muted"])
        font = theme.font("body", weight="medium" if selected else "regular")
        painter.setFont(font)
        right = r.right() - 10
        count = index.data(COUNT_ROLE)
        if count:
            painter.setFont(theme.font("caption"))
            w = painter.fontMetrics().horizontalAdvance(count)
            painter.setPen(QColor(t["text_faint"] if not selected else t["text_muted"]))
            painter.drawText(QRectF(right - w, r.top(), w, r.height()), Qt.AlignVCenter | Qt.AlignRight, count)
            right -= w + 8
            painter.setFont(font)
        painter.setPen(QColor(t["text"] if strong else t["text_muted"]))
        left = r.left() + 18 + size
        painter.drawText(QRectF(left, r.top(), max(right - left, 0), r.height()), Qt.AlignVCenter | Qt.AlignLeft,
                         painter.fontMetrics().elidedText(index.data(Qt.DisplayRole), Qt.ElideRight,
                                                          int(max(right - left, 0))))
        painter.restore()


class _HoverButton(QPushButton):
    """Flat button that paints itself and repaints on hover."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WA_Hover)
        self.setCursor(Qt.PointingHandCursor)
        self.setFocusPolicy(Qt.NoFocus)

    def enterEvent(self, event):
        self.update()
        super().enterEvent(event)

    def leaveEvent(self, event):
        self.update()
        super().leaveEvent(event)


class WorkspaceButton(_HoverButton):
    """Workspace tile + name + chevron; opens the app menu."""

    def __init__(self, name, parent=None):
        super().__init__(parent)
        self.name = name
        self.setToolTip("Network Vulnerability Explorer: commands, export, theme, settings")

    def sizeHint(self):
        return QSize(180, max(34, self.fontMetrics().height() + 16))

    def paintEvent(self, _event):
        t = theme.tokens()
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        r = QRectF(self.rect())
        if self.underMouse() or self.isDown():
            p.setPen(Qt.NoPen)
            p.setBrush(QColor(t["hover"]))
            p.drawRoundedRect(r, 6, 6)
        tile = QRectF(8, r.center().y() - 11, 22, 22)
        p.setPen(Qt.NoPen)
        p.setBrush(QColor(theme.BRAND["blue"]))
        p.drawRoundedRect(tile, 6, 6)
        p.setPen(QColor("#FFFFFF"))
        f = theme.font("caption", weight="semibold")
        f.setPixelSize(max(round(f.pixelSize() * 0.85), 8))
        p.setFont(f)
        p.drawText(tile, Qt.AlignCenter, "UF")
        p.setFont(theme.font("body", weight="semibold"))
        p.setPen(QColor(t["text"]))
        w = p.fontMetrics().horizontalAdvance(self.name)
        p.drawText(QRectF(38, 0, w + 2, r.height()), Qt.AlignVCenter | Qt.AlignLeft, self.name)
        icons.paint(p, "chevron-down", QRectF(38 + w + 6, r.center().y() - 6, 12, 12), t["text_muted"])
        p.end()


class SearchButton(_HoverButton):
    """Looks like a search box; opens the command palette."""

    def sizeHint(self):
        return QSize(180, max(30, self.fontMetrics().height() + 14))

    def paintEvent(self, _event):
        t = theme.tokens()
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        r = QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5)
        p.setPen(QColor(t["border_strong"] if self.underMouse() else t["border"]))
        p.setBrush(QColor(t["surface"]))
        p.drawRoundedRect(r, 6, 6)
        icons.paint(p, "search", QRectF(10, r.center().y() - 7.5, 15, 15), t["text_faint"])
        p.setFont(theme.font("body"))
        p.setPen(QColor(t["text_muted"]))
        p.drawText(QRectF(32, 0, r.width() - 90, r.height()), Qt.AlignVCenter | Qt.AlignLeft, "Search…")
        p.setFont(theme.font("caption", weight="medium"))
        x = r.right() - 7
        for key in ("K", "Ctrl"):
            w = max(p.fontMetrics().horizontalAdvance(key) + 10, 18)
            cap = QRectF(x - w, r.center().y() - 9, w, 18)
            p.setPen(QColor(t["kbd_border"]))
            p.setBrush(QColor(t["kbd_bg"]))
            p.drawRoundedRect(cap, 4, 4)
            p.setPen(QColor(t["kbd_text"]))
            p.drawText(cap, Qt.AlignCenter, key)
            x -= w + 3
        p.end()


class NavButton(_HoverButton):
    """A sidebar row outside the view list (Settings)."""

    def __init__(self, text, icon_name, parent=None):
        super().__init__(parent)
        self.text_, self.icon_name = text, icon_name

    def sizeHint(self):
        return QSize(180, self.fontMetrics().height() + 14)

    def paintEvent(self, _event):
        t = theme.tokens()
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        r = QRectF(self.rect())
        hover = self.underMouse()
        if hover:
            p.setPen(Qt.NoPen)
            p.setBrush(QColor(t["hover"]))
            p.drawRoundedRect(r, 6, 6)
        size = round(self.fontMetrics().height() * 0.95)
        icons.paint(p, self.icon_name, QRectF(10, r.center().y() - size / 2, size, size), t["text_muted"])
        p.setFont(theme.font("body"))
        p.setPen(QColor(t["text"] if hover else t["text_muted"]))
        p.drawText(QRectF(18 + size, 0, r.width(), r.height()), Qt.AlignVCenter | Qt.AlignLeft, self.text_)
        p.end()


# ---- dialogs ----------------------------------------------------------------------------------------

class GlossaryDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Glossary")
        self.resize(620, 640)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(10)
        layout.addWidget(label("Glossary", "headline"))
        layout.addWidget(label("Plain-English definitions of the terms used across the app.", "body", "Muted"))
        self.search = SearchField("Filter terms…")
        self.search.textChanged.connect(self.render)
        self.view = QTextBrowser()
        layout.addWidget(self.search)
        layout.addWidget(self.view, 1)
        self.render()

    def render(self, *_):
        words = self.search.text().lower().split()
        terms = [(k, v) for k, v in glossary.TERMS.items() if all(w in f"{k} {v}".lower() for w in words)]
        self.view.document().setDefaultStyleSheet(detail_css())
        self.view.setHtml("".join(f"<p style='margin-bottom:12px'><b>{html.escape(k)}</b><br>"
                                  f"<span class='muted'>{html.escape(v)}</span></p>" for k, v in terms)
                          or "<p class='muted'>No matching terms.</p>")


class ShortcutsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Keyboard shortcuts")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(12)
        layout.addWidget(label("Keyboard shortcuts", "headline"))
        grid = QGridLayout()
        grid.setHorizontalSpacing(24)
        grid.setVerticalSpacing(10)
        for row, (keys, text) in enumerate(SHORTCUTS):
            grid.addWidget(label(text), row, 0)
            caps = QHBoxLayout()
            caps.setSpacing(4)
            caps.addStretch(1)
            for key in keys:
                caps.addWidget(Kbd(key))
            grid.addLayout(caps, row, 1)
        layout.addLayout(grid)
        close = button("Close")
        close.clicked.connect(self.accept)
        row = QHBoxLayout()
        row.addStretch(1)
        row.addWidget(close)
        layout.addLayout(row)


# ---- main window ----------------------------------------------------------------------------------

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
        self.trends_view = None
        self.changes, self.history_series = None, pd.DataFrame()
        self.actions, self.action_members = pd.DataFrame(), {}
        self._cache_signature = None
        self._pending = {}  # view key -> loads the latest data into a view that hasn't been shown yet
        self._palette_targets = None
        self.presenting = False
        self.search_targets = {}
        self.setWindowTitle(APP_TITLE)
        self.resize(1440, 900)

        self.toast = None
        self._build_pages()
        self._build_actions()
        sidebar = self._build_sidebar()
        header = self._build_header()
        self.stack = PageStack()  # 0 = getting started (no data), 1 = pages
        self.stack.addWidget(self._empty_page())
        pages_box = QWidget()
        pages_layout = QVBoxLayout(pages_box)
        pages_layout.setContentsMargins(1, 0, 1, 8)  # keeps full-width tables inside the rounded corners
        pages_layout.addWidget(self.pages)
        self.stack.addWidget(pages_box)
        content = QFrame()
        content.setObjectName("ContentPanel")
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(0)
        content_layout.addWidget(header)
        content_layout.addWidget(self.stack, 1)
        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 8, 8, 8)
        right_layout.addWidget(content)
        central = QWidget()
        central.setObjectName("AppRoot")
        outer = QHBoxLayout(central)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        outer.addWidget(sidebar)
        outer.addWidget(right, 1)
        self.setCentralWidget(central)
        self.command_palette = CommandPalette(self, fallback=lambda text: self.navigate("findings", text=text))
        self.nav.setCurrentRow(0)
        self._page_changed(0)

        self.findings_tab.count_changed.connect(self._update_status)
        self.toast = Toast(self)
        self._theme_mode = theme.mode()
        theme.signals.changed.connect(self._retheme)
        self._follows_theme = True

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
    # Views other than the one showing get their data on first use (navigation or attribute access),
    # so opening a large dataset only pays for the Overview.
    findings_tab = property(lambda self: self._ready("findings"))
    devices_tab = property(lambda self: self._ready("devices"))
    remediation_view = property(lambda self: self._ready("remediation"))
    hardware_view = property(lambda self: self._ready("hardware"))

    def _ready(self, key):
        load = self._pending.pop(key, None)
        if load is not None:
            QApplication.setOverrideCursor(Qt.WaitCursor)
            try:
                load()
            finally:
                QApplication.restoreOverrideCursor()
        return self.views[key]

    def _defer(self, key, load):
        self._pending[key] = load
        if self.pages.currentWidget() is self.views[key]:
            self._ready(key)

    def _build_pages(self):
        from tenable_net.gui.hardware import HardwareView
        from tenable_net.gui.remediation import RemediationView

        self.overview = OverviewTab()
        self.views = {"overview": self.overview, "findings": FindingsTab(), "devices": DevicesTab(),
                      "remediation": RemediationView(), "hardware": HardwareView()}
        self.overview.device_activated.connect(lambda h: self.navigate("devices", hostname=h))
        self.overview.plugin_activated.connect(lambda p: self.navigate("findings", text=p))
        self.overview.severity_activated.connect(lambda s: self.navigate("findings", severity=s))
        self.overview.view_requested.connect(lambda view, filters: self.navigate(view, **filters))
        self.pages = PageStack()
        self.remediation_view.device_activated.connect(lambda h: self.navigate("devices", hostname=h))
        self.overview.action_activated.connect(lambda a: self.navigate("remediation", action=a))
        self.hardware_view.device_activated.connect(lambda h: self.navigate("devices", hostname=h))
        self.hardware_view.pull_requested.connect(self.pull)
        self.view_keys = []
        for key, *_rest in NAV:
            page = self.views.get(key) or QWidget()  # lazily-built views start as placeholders
            self.views[key] = page
            self.pages.addWidget(page)
            self.view_keys.append(key)
        self.tabs = self.pages  # older name, still used by scripts

    def _build_header(self):
        """Slim bar across the top of the content panel: page icon, title, subtitle and the main actions."""
        bar = QFrame()
        bar.setObjectName("PageHeader")
        bar.setMinimumHeight(50)
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(18, 8, 10, 8)
        layout.setSpacing(8)
        self.page_icon = QLabel()
        self.page_icon.setFixedSize(16, 16)
        self.page_title = label("", "title", "PageTitle")
        self.page_subtitle = elided("", "body", "PageSubtitle")
        layout.addWidget(self.page_icon)
        layout.addSpacing(2)
        layout.addWidget(self.page_title)
        layout.addSpacing(6)
        layout.addWidget(self.page_subtitle)
        layout.addStretch(1)

        self.report_button = MenuButton("Export", variant="ghost")
        self.report_button.setToolTip("Excel report, executive summary (PDF), or this view as an image")
        export_menu = QMenu(self.report_button)
        for action in (self.report_action, self.summary_action, self.image_action):
            export_menu.addAction(action)
        self.report_button.setMenu(export_menu)
        self.present_button = button("Present", "ghost", "present",
                                     "Presentation mode for meetings (F11): larger type, summary views only")
        self.present_button.clicked.connect(self.toggle_presentation)
        self.pull_button = button("Pull from Tenable", "primary", "pull", "Pull fresh data from Tenable (Ctrl+P)")
        self.pull_button.clicked.connect(self.pull)
        for b in (self.report_button, self.present_button):
            layout.addWidget(b)
        layout.addSpacing(4)
        layout.addWidget(self.pull_button)
        return bar

    def _build_sidebar(self):
        """Workspace menu, search, views with counts, data-source status, settings."""
        sidebar = self.sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(SIDEBAR_WIDTH)
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(10, 10, 8, 10)
        layout.setSpacing(2)
        self.workspace_button = WorkspaceButton(WORKSPACE)
        self.workspace_button.clicked.connect(self._show_app_menu)
        layout.addWidget(self.workspace_button)
        layout.addSpacing(6)
        self.search_button = SearchButton()
        self.search_button.setToolTip("Search devices, CVEs, plugins, models and serials, or run a command (Ctrl+K)")
        self.search_button.clicked.connect(self.open_palette)
        layout.addWidget(self.search_button)
        layout.addSpacing(10)

        self.nav = QListWidget()
        self.nav.setObjectName("NavList")
        self.nav.setFocusPolicy(Qt.NoFocus)
        self.nav.setMouseTracking(True)
        self.nav.viewport().setAttribute(Qt.WA_Hover)
        self.nav.setItemDelegate(NavDelegate(self.nav))
        self.nav.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.nav.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.nav_items = {}
        for key, nav_label, _title, _sub, icon in NAV:
            if key in NAV_SECTIONS:
                header = QListWidgetItem(NAV_SECTIONS[key])
                header.setData(HEADER_ROLE, True)
                header.setFlags(Qt.NoItemFlags)
                self.nav.addItem(header)
            item = QListWidgetItem(nav_label)
            item.setData(Qt.UserRole, key)
            item.setData(ICON_ROLE, icon)
            self.nav.addItem(item)
            self.nav_items[key] = item
        self.nav.currentItemChanged.connect(self._nav_changed)
        self.pages.currentChanged.connect(self._page_changed)
        layout.addWidget(self.nav)
        self._fit_nav()
        layout.addStretch(1)

        sources = label("Data sources", "caption", "SidebarCaption", weight="medium")
        layout.addWidget(sources)
        layout.addSpacing(2)
        self.fresh_chip = Chip("No data")
        self.fresh_chip.clicked.connect(self.pull)
        self.source_chips = {name: Chip(name) for name in ("Tenable", "AKiPS", "Cisco")}
        self.source_chips["Tenable"].clicked.connect(self.open_settings)
        self.source_chips["AKiPS"].clicked.connect(lambda: self.navigate("diagnostics"))
        self.source_chips["Cisco"].clicked.connect(lambda: self.navigate("diagnostics"))
        for chip in (self.fresh_chip, *self.source_chips.values()):
            layout.addWidget(chip)
        layout.addSpacing(8)
        self.settings_button = NavButton("Settings", "settings")
        self.settings_button.setToolTip("Tenable, AKiPS and Cisco connections (Ctrl+,)")
        self.settings_button.clicked.connect(self.open_settings)
        layout.addWidget(self.settings_button)
        version = label(f"v{__version__} · Network Engineering", "caption", "SidebarVersion")
        version.setContentsMargins(10, 6, 0, 0)
        layout.addWidget(version)
        return sidebar

    def _fit_nav(self):
        height = sum(self.nav.sizeHintForRow(r) for r in range(self.nav.count()) if not self.nav.item(r).isHidden())
        self.nav.setFixedHeight(height + 4)

    def _empty_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addStretch(2)
        card = QFrame()
        card.setObjectName("EmptyCard")
        card.setFixedWidth(500)
        inner = QVBoxLayout(card)
        inner.setContentsMargins(28, 26, 28, 24)
        inner.setSpacing(8)
        self.empty_icon = QLabel()
        self.empty_icon.setFixedSize(40, 40)
        self.empty_icon.setAlignment(Qt.AlignCenter)
        inner.addWidget(self.empty_icon)
        inner.addSpacing(6)
        inner.addWidget(label("Get started", "headline"))
        self.empty_note = label("Pull your findings from Tenable to see where the network stands.", "body", "Muted",
                                wrap=True)
        inner.addWidget(self.empty_note)
        inner.addSpacing(4)
        self.checklist = QLabel()
        self.checklist.setTextFormat(Qt.RichText)
        self.checklist.setWordWrap(True)
        inner.addWidget(self.checklist)
        inner.addSpacing(10)
        pull = button("Pull from Tenable…", "primary", "pull")
        pull.clicked.connect(self.pull)
        keys = button("Settings…", icon_name="settings")
        keys.clicked.connect(self.open_settings)
        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        buttons.addWidget(pull)
        buttons.addWidget(keys)
        buttons.addStretch(1)
        inner.addLayout(buttons)
        layout.addWidget(card, alignment=Qt.AlignCenter)
        layout.addStretch(3)
        self._retheme_empty()
        return page

    def _retheme_empty(self):
        t = theme.tokens()
        self.empty_icon.setPixmap(icons.pixmap("database", t["text_muted"], 20))
        self.empty_icon.setStyleSheet(f"background: {t['surface_alt']}; border: 1px solid {t['border']}; "
                                      "border-radius: 10px;")

    def _action(self, text, slot, shortcut=None, icon_name=None, checkable=False):
        action = QAction(text, self)
        if shortcut:
            action.setShortcut(QKeySequence(shortcut))
        if checkable:
            action.setCheckable(True)
            action.triggered.connect(lambda _c=False: slot())
        else:
            action.triggered.connect(lambda _c=False: slot())
        action.setProperty("icon_name", icon_name or "")
        self.addAction(action)  # shortcuts work without a menu bar
        return action

    def _build_actions(self):
        self.pull_action = self._action("Pull from Tenable…", self.pull, "Ctrl+P", "pull")
        self.reload_action = self._action("Reload cache", self.reload, QKeySequence.Refresh, "reload")
        self.report_action = self._action("Excel report (all sheets)", self.export_report, "Ctrl+E", "file")
        self.summary_action = self._action("Executive summary (PDF)…", self.export_summary, "Ctrl+Shift+E", "file")
        self.image_action = self._action("Current view as image (PNG)…", self.export_view_image, "Ctrl+Shift+S",
                                         "image")
        self.present_action = self._action("Presentation mode", self.toggle_presentation, "F11", "present",
                                           checkable=True)
        self.settings_action = self._action("Settings…", self.open_settings, "Ctrl+,", "settings")
        self.diagnostics_action = self._action("Enrichment diagnostics", self.open_diagnostics, None, "diagnostics")
        self.diagnostics_action.setToolTip("Why devices are missing hardware / Cisco data")
        self.palette_action = self._action("Command palette…", self.open_palette, "Ctrl+K", "search")
        self.find_action = self._action("Find", self.focus_search, QKeySequence.Find)
        self.shortcuts_action = self._action("Keyboard shortcuts", lambda: ShortcutsDialog(self).exec(), "Ctrl+/",
                                             "keyboard")
        self.glossary_action = self._action("Glossary", lambda: GlossaryDialog(self).exec(), None, "book")
        self.about_action = self._action("About", self.about, None, "info")
        self.quit_action = self._action("Quit", self.close, "Ctrl+Q", "power")
        self.view_actions = {}
        for i, (key, nav_label, *_rest) in enumerate(NAV, start=1):
            self.view_actions[key] = self._action(f"Go to {nav_label}", lambda k=key: self.navigate(k), f"Ctrl+{i}",
                                                  _rest[-1])
        self.theme_group = QActionGroup(self)
        current = self.settings.value("theme", "system")
        self.theme_actions = {}
        for name, icon_name in (("system", "monitor"), ("light", "sun"), ("dark", "moon")):
            act = QAction(name.title(), self, checkable=True, checked=name == current)
            act.setProperty("icon_name", icon_name)
            act.triggered.connect(lambda _=False, t=name: self.set_theme(t))
            self.theme_group.addAction(act)
            self.theme_actions[name] = act

        menu = self.app_menu = QMenu(self)
        for action in (self.pull_action, self.reload_action):
            menu.addAction(action)
        menu.addSeparator()
        export_menu = menu.addMenu("Export")
        export_menu.setProperty("icon_name", "export")
        self._export_submenu = export_menu
        for action in (self.report_action, self.summary_action, self.image_action):
            export_menu.addAction(action)
        menu.addAction(self.present_action)
        theme_menu = menu.addMenu("Theme")
        self._theme_submenu = theme_menu
        for act in self.theme_actions.values():
            theme_menu.addAction(act)
        menu.addSeparator()
        menu.addAction(self.settings_action)
        menu.addAction(self.diagnostics_action)
        menu.addSeparator()
        for action in (self.palette_action, self.shortcuts_action, self.glossary_action, self.about_action):
            menu.addAction(action)
        menu.addSeparator()
        menu.addAction(self.quit_action)
        self._tint_actions()

    def _tint_actions(self):
        t = theme.tokens()
        for action in self.findChildren(QAction):
            name = action.property("icon_name")
            if name:
                action.setIcon(icons.icon(name, t["text_muted"]))
        self._export_submenu.setIcon(icons.icon("export", t["text_muted"]))
        self._theme_submenu.setIcon(icons.icon("sun" if theme.mode() == "light" else "moon", t["text_muted"]))

    def _show_app_menu(self):
        self.app_menu.exec(self.workspace_button.mapToGlobal(self.workspace_button.rect().bottomLeft()))

    def about(self):
        QMessageBox.about(self, "About", f"<b>{APP_TITLE}</b><br>tenable_net {__version__}<br>"
                                         "Tenable vulnerability explorer for UF Health network equipment.<br><br>"
                                         "Set in Inter (SIL Open Font License).")

    # ---- navigation -------------------------------------------------------------
    def _nav_changed(self, item, _previous=None):
        if item is not None and item.data(Qt.UserRole):
            self.show_view(item.data(Qt.UserRole))

    def _page_changed(self, index):
        key = self.view_keys[index]
        self.nav.blockSignals(True)
        self.nav.setCurrentItem(self.nav_items[key])
        self.nav.blockSignals(False)
        self.nav.viewport().update()
        title, subtitle, icon_name = NAV_INFO[key]
        self.page_title.setText(title)
        self.page_subtitle.setText(subtitle)
        self.page_icon.setPixmap(icons.pixmap(icon_name, theme.tokens()["text_muted"], 16))

    def current_view(self):
        return self.view_keys[self.pages.currentIndex()]

    def show_view(self, key):
        page = self._ensure_view(key)
        if self.pages.currentWidget() is not page:
            self.pages.setCurrentWidget(page)
        return page

    def _ensure_view(self, key):
        """Build lazily-created views on first use, and load any data they haven't had yet."""
        page = self._ready(key)
        if key == "diagnostics" and self.diagnostics_window is None:
            from tenable_net.gui.diagnostics_window import DiagnosticsWindow

            self.diagnostics_window = DiagnosticsWindow(self.cache_dir, self, embedded=True)
            self._replace_page(key, self.diagnostics_window)
            page = self.diagnostics_window
        elif key == "diagnostics":
            self.diagnostics_window.reload()
        elif key == "trends" and self.trends_view is None:
            from tenable_net.gui.trends import TrendsView

            self.trends_view = TrendsView(self.cache_dir)
            self.trends_view.view_requested.connect(lambda view, filters: self.navigate(view, **filters))
            self._replace_page(key, self.trends_view)
            page = self.trends_view
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
        if view == "findings" and (filters.get("text") is not None or filters.get("severity")
                                   or filters.get("exploitable") or filters.get("changed")):
            page.show_query(filters.get("text") or "", severity=filters.get("severity"),
                            exploitable=filters.get("exploitable", False), changed=filters.get("changed", False))
        elif view == "devices" and filters.get("hostname"):
            page.select_device(filters["hostname"])
        elif view == "devices" and filters.get("lifecycle"):
            page.search.clear()
            page.lifecycle_filter.setCurrentText(filters["lifecycle"])
        elif view == "hardware" and filters.get("filter"):
            page.select_filter(filters["filter"])
        elif view == "remediation" and filters.get("action"):
            page.select_action(filters["action"])
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
        """Ctrl+F: the current view's own search box (Findings when the view has none)."""
        page = self.pages.currentWidget()
        search = getattr(page, "search", None)
        if search is None or self.current_view() in ("overview", "trends"):
            self.navigate("findings")
            search = self.findings_tab.search
        search.setFocus()
        search.selectAll()

    def focus_global_search(self):
        self.open_palette()

    # ---- command palette + search targets -------------------------------------------
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
        self._palette_targets = None

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

    def _target_entries(self):
        if self._palette_targets is None:
            kinds = {"Device": ("Devices", "devices"), "CVE": ("CVEs", "shield"), "Plugin": ("Plugins", "code"),
                     "Model": ("Models", "hardware"), "Serial": ("Serials", "hash")}
            entries = []
            for key in self.search_targets:
                kind, _, rest = key.partition(" · ")
                group, icon_name = kinds.get(kind, (kind, "arrow-right"))
                if kind == "Plugin":
                    pid, _, name = rest.partition(" · ")
                    title, subtitle = name or pid, f"Plugin {pid}"
                elif kind == "Serial":
                    title, _, subtitle = rest.partition(" · ")
                else:
                    title, subtitle = rest, kind
                entries.append(Entry(title, group, icon_name, subtitle, run=lambda k=key: self._search_activated(k)))
            self._palette_targets = entries
        return self._palette_targets

    def palette_entries(self):
        entries = [Entry(f"Go to {nav_label}", "Go to", icon_name, keys=shortcut_keys(self.view_actions[key].shortcut()),
                         run=lambda k=key: self.navigate(k))
                   for key, nav_label, _t, _s, icon_name in NAV
                   if not self.presenting or key in PRESENT_VIEWS]
        commands = [self.pull_action, self.reload_action, self.report_action, self.summary_action, self.image_action,
                    self.present_action, self.settings_action, self.shortcuts_action, self.glossary_action,
                    self.about_action]
        for action in commands:
            if action.isEnabled():
                entries.append(Entry(action.text().replace("…", ""), "Commands", action.property("icon_name") or
                                     "arrow-right", keys=shortcut_keys(action.shortcut()), run=action.trigger))
        for name, act in self.theme_actions.items():
            entries.append(Entry(f"Theme: {name.title()}", "Commands", act.property("icon_name"), run=act.trigger))
        return entries + self._target_entries()

    def open_palette(self):
        self.command_palette.open(self.palette_entries())

    # ---- theme ---------------------------------------------------------------------
    def set_theme(self, mode_name):
        self.settings.setValue("theme", mode_name)
        if mode_name in self.theme_actions:
            self.theme_actions[mode_name].setChecked(True)
        theme.apply(QApplication.instance(), mode_name, presentation=self.presenting)

    def _retheme(self, mode_name=None):
        """The theme changed: re-tint icons and rebuild anything that baked colours in. Presentation mode
        re-applies the same light/dark mode (and reloads anyway), so it only needs the cheap part."""
        self._tint_actions()
        self._retheme_empty()
        self._page_changed(self.pages.currentIndex())
        self._update_header()
        self._update_checklist()
        if mode_name == self._theme_mode:
            return
        self._theme_mode = mode_name
        if not self.findings.empty:
            self.overview.set_data(self.findings, self.inventory)  # charts pick up theme colours when built
            self.overview.set_history(self.changes, self.history_series)
            self.overview.set_actions(self.actions)
        for view in self.views.values():
            if hasattr(view, "refresh_theme") and view is not self.overview:
                view.refresh_theme()
        self.update()

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

    def _set_data_actions(self, enabled):
        for widget in (self.report_action, self.summary_action, self.image_action, self.report_button,
                       self.present_button, self.present_action):
            widget.setEnabled(enabled)

    def reload(self):
        self._rewatch()
        self._cache_signature = self._signature()
        self._update_checklist()
        try:
            vulns, assets, self.meta = export.load_cache(self.cache_dir)
        except FileNotFoundError:
            self.stack.setCurrentIndex(0)
            self._set_data_actions(False)
            self.empty_note.setText("Pull your findings from Tenable to see where the network stands.")
            self.empty_note.setToolTip(f"Nothing is cached in {self.cache_dir.resolve()} yet.")
            self._update_header()
            self._update_counts()
            return
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            findings = normalize.findings_frame(vulns, include_info=True)
            findings["vendor"] = findings["os"].map(normalize.vendor_of)
            findings = risk.add_finding_scores(findings)
            self.changes, self.history_series = self._load_history(findings)
            labels = {}
            if self.changes:
                labels.update({k: "New" for k in self.changes["new"]["key"]})
                labels.update({k: "Reopened" for k in self.changes["reopened"]["key"]})
            findings["change"] = history.finding_keys(findings).map(labels).fillna("") if labels else ""
            self.findings = findings
            self.assets = normalize.assets_frame(assets)
            self.inventory = inventory.load_inventory(self.cache_dir, vulns, assets)
            self.overview.set_data(findings, self.inventory)
            self.overview.set_history(self.changes, self.history_series)
            self.actions, self.action_members = remediation.plan(findings, self.inventory)
            self.overview.set_actions(self.actions)
            total_risk = findings.loc[findings["severity"].astype(str) != "info", "risk"].sum()
            self._defer("remediation", lambda: self.views["remediation"].set_data(
                self.actions, self.action_members, total_risk))
            self._defer("findings", lambda: self.views["findings"].set_data(findings))
            self._defer("devices", lambda: self._load_devices(findings, vulns, assets))
            self._defer("hardware", lambda: self.views["hardware"].set_data(self.inventory))
            if self.trends_view is not None:
                self.trends_view.reload()
            if self.diagnostics_window is not None:
                self.diagnostics_window.reload()
            self._build_search_index()
        finally:
            QApplication.restoreOverrideCursor()
        self.stack.setCurrentIndex(1)
        self._set_data_actions(True)
        self._update_status()
        self._update_header()

    def _load_devices(self, findings, vulns, assets):
        view = self.views["devices"]
        view.history_dir = self.cache_dir
        view.set_data(findings, self.assets, self.inventory, self._enrichment_status(vulns, assets))

    def _load_history(self, findings=None):
        """Make sure history exists (backfill on first run), then return (changes, series)."""
        try:
            history.ensure_backfill(self.cache_dir, findings=findings, meta=self.meta)
            return history.changes(self.cache_dir), history.series(self.cache_dir)
        except Exception:  # noqa: BLE001 - history is a bonus; never block loading
            return None, pd.DataFrame()

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

    def _scope_text(self):
        filters = self.meta.get("filters") or {}
        sev = ", ".join(filters.get("severity") or []) or "all"
        state = ", ".join(filters.get("state") or []) or "all"
        since = f" · last {filters['since_days']} days" if filters.get("since_days") else ""
        return f"Severity: {sev} · state: {state}{since}"

    def _update_header(self):
        text, hours = _ago(self.meta.get("pulled_at"))
        if text is None:
            self.fresh_chip.set("No data yet", "bad", "No data pulled yet. Click to pull from Tenable.")
        else:
            status = "good" if hours < 24 else ("warn" if hours < 24 * 7 else "bad")
            self.fresh_chip.set(f"Pulled {text}", status,
                                f"Last pull: {self.meta.get('pulled_at')}<br>{html.escape(self._scope_text())}<br>"
                                "Amber after 24 h, red after 7 days. Click to pull again.")
        access, secret = client.saved_credentials()
        self.source_chips["Tenable"].set("Tenable", "good" if access and secret else "bad",
                                         "Tenable API keys saved" if access and secret else
                                         "No Tenable API keys: click to open Settings",
                                         "" if access and secret else "no keys")
        if akips.configured():
            rows, _ = inventory._read(self.cache_dir, inventory.AKIPS_FILE)
            self.source_chips["AKiPS"].set("AKiPS", "good" if rows else "warn",
                                           f"{len(rows):,} chassis from AKiPS" if rows else
                                           "Configured; no inventory pulled yet",
                                           f"{len(rows):,} chassis" if rows else "")
        else:
            self.source_chips["AKiPS"].set("AKiPS", "neutral", "AKiPS not configured (optional)", "off")
        if cisco.configured():
            run = cisco.load_cache(self.cache_dir).get("last_run") or {}
            status = "bad" if run.get("errors") else ("good" if run else "warn")
            tip = ("Last Cisco run had errors: " + "; ".join(run.get("errors"))[:300] if run.get("errors") else
                   f"Last Cisco lookup {run.get('at')}" if run else "Configured; no lookups yet")
            self.source_chips["Cisco"].set("Cisco", status, tip + ". Click for diagnostics.",
                                           "errors" if run.get("errors") else "")
        else:
            self.source_chips["Cisco"].set("Cisco", "neutral", "Cisco APIs not configured (optional)", "off")

    def _update_checklist(self):
        access, secret = client.saved_credentials()
        steps = [
            ("Save your Tenable API keys (Settings)", bool(access and secret)),
            ("Pull findings from Tenable", (self.cache_dir / export.VULNS_FILE).exists()),
            ("Optional: connect AKiPS for hardware models and serials", akips.configured()),
            ("Optional: connect Cisco APIs for contracts and software suggestions", cisco.configured()),
        ]
        t = theme.tokens()
        self.checklist.setText("".join(
            f"<p style='margin:6px 0'><span style='color:{t['dot_good'] if done else t['text_faint']}'>"
            f"{'✓' if done else '○'}</span>&nbsp;&nbsp;<span style='color:{t['text'] if not done else t['text_muted']}'>"
            f"{html.escape(label_)}</span></p>" for label_, done in steps))

    def _update_counts(self):
        f = self.findings
        hosts = set(f["hostname"].dropna()) if not f.empty else set()
        if not self.assets.empty:
            hosts |= set(self.assets["hostname"].dropna())
        if not self.inventory.empty:
            hosts |= set(self.inventory["hostname"].dropna())
        counts = {"findings": len(f), "devices": len(hosts), "remediation": len(self.actions),
                  "hardware": len(self.inventory)}
        for key, item in self.nav_items.items():
            n = counts.get(key)
            item.setData(COUNT_ROLE, f"{n:,}" if n else "")

    def _update_status(self, *_):
        self._update_counts()

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
            paths = reports.write_reports(self.findings.drop(columns=["vendor", "risk", "days_open", "change"],
                                                             errors="ignore"),
                                          self.assets, inventory=self.inventory,
                                          plan=(self.actions, self.action_members))
        finally:
            QApplication.restoreOverrideCursor()
        folder = paths[0].parent.resolve()
        self.notify(f"Report written to {folder}")
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(folder)))

    # ---- presentation + exports ----------------------------------------------------------
    def toggle_presentation(self):
        """Meeting mode: larger type, full screen, summary views only. F11 / Esc toggles back."""
        self.presenting = not self.presenting
        self.present_action.setChecked(self.presenting)
        theme.apply(QApplication.instance(), self.settings.value("theme", "system"), presentation=self.presenting)
        theme.refresh_fonts(self)
        for widget in (self.search_button, self.pull_button, self.page_subtitle):
            widget.setVisible(not self.presenting)
        self.present_button.setText("Exit presentation" if self.presenting else "Present")
        self.sidebar.setFixedWidth(round(SIDEBAR_WIDTH * (1.15 if self.presenting else 1)))
        for row in range(self.nav.count()):
            item = self.nav.item(row)
            item.setHidden(self.presenting and item.data(Qt.UserRole) not in PRESENT_VIEWS)
        self._fit_nav()
        for b in (self.workspace_button, self.search_button, self.settings_button, self.fresh_chip,
                  *self.source_chips.values()):
            b.setFont(theme.font("body"))
            b.updateGeometry()
        if self.presenting:
            self._was_maximized = self.isMaximized()
            if self.current_view() not in PRESENT_VIEWS:
                self.navigate("overview")
            self.showFullScreen()
        else:
            self.showMaximized() if getattr(self, "_was_maximized", False) else self.showNormal()
        if not self.findings.empty:
            self.reload()  # re-fit tables and charts to the new type scale

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Escape and self.presenting:
            self.toggle_presentation()
            return
        super().keyPressEvent(event)

    def export_view_image(self, path=None):
        page = self.pages.currentWidget()
        if path is None:
            path, _ = QFileDialog.getSaveFileName(self, "Save view as image", f"{self.current_view()}.png", "PNG (*.png)")
        if path:
            page.grab().save(str(path))
            self.notify(f"Saved {path}")
        return path

    def summary_data(self):
        """Everything the executive summary needs, from the loaded data."""
        fleet = risk.fleet_summary(self.overview.device_risk)
        ch = self.changes
        d = ch["deltas"] if ch else {}
        sev = self.findings["severity"].astype(str) if not self.findings.empty else pd.Series(dtype=str)
        kpis = [
            ("Critical findings", f"{int((sev == 'critical').sum()):,}", d.get("critical"), True),
            ("High findings", f"{int((sev == 'high').sum()):,}", d.get("high"), True),
            ("Exploit available", f"{int((self.findings.get('exploit_available') == True).sum()):,}",  # noqa: E712
             d.get("exploitable"), True),
            ("Devices at Critical/High risk", f"{fleet['counts']['Critical'] + fleet['counts']['High']:,}",
             (d.get("Critical", 0) + d.get("High", 0)) if ch else None, True),
        ]
        hw = None
        if not self.inventory.empty:
            c = self.inventory[self.inventory["vendor"] == "Cisco"]
            soon = c["contract_end"].notna() & (c["contract_end"] <= pd.Timestamp.now() + pd.Timedelta(days=90))
            hw = {"chassis": len(c), "covered": int((c["contract"] == "Covered").sum()),
                  "uncovered": int((c["contract"] == "Not covered").sum()), "expiring": int(soon.sum()),
                  "upgrade": int((c["sw_status"] == "Upgrade suggested").sum())}
        images = {}

        from tenable_net.gui.charts import render_image

        images["severity"] = (render_image(self.overview.sev_chart), "Findings by severity")
        if len(history.list_snapshots(self.cache_dir)) >= 2:
            tv = self.trends_view or self._ensure_view("trends")  # the real page, not a throwaway widget
            images["trend"] = (render_image(tv.open_chart), "Open findings over time")
        return {"fleet": fleet, "kpis": kpis, "changes": ch, "actions": self.actions,
                "devices": self.overview.device_risk, "hardware": hw, "images": images,
                "pulled_at": str(self.meta.get("pulled_at", ""))[:16].replace("T", " "),
                "driver": self.overview.driver_text("light")}

    def export_summary(self, path=None):
        from tenable_net.gui.executive_summary import render_pdf

        if self.findings.empty:
            return None
        if path is None:
            path, _ = QFileDialog.getSaveFileName(self, "Executive summary", "network_vulnerability_summary.pdf",
                                                  "PDF (*.pdf)")
        if not path:
            return None
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            render_pdf(path, self.summary_data())
        finally:
            QApplication.restoreOverrideCursor()
        self.notify(f"Executive summary saved to {path}")
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(Path(path).resolve())))
        return path

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if self.toast is not None and self.toast.isVisible():
            self.toast.reposition()
        palette = getattr(self, "command_palette", None)
        if palette is not None and palette.isVisible():
            palette.place()

    def closeEvent(self, event):
        self.settings.setValue("geometry", self.saveGeometry())
        if self._follows_theme:  # a closed window no longer follows theme changes
            theme.signals.changed.disconnect(self._retheme)
            self._follows_theme = False
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
