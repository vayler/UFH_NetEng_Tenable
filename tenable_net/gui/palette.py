"""Command palette (Ctrl+K): one box to run any command or jump to a device, CVE, plugin, model or serial.

Results are grouped (Commands, Devices, CVEs, …); arrow keys move, Enter opens, Esc closes. Typing that
matches nothing falls back to searching the findings for the text.
"""

from dataclasses import dataclass, field
from typing import Callable

from PySide6.QtCore import QAbstractListModel, QModelIndex, QRectF, QSize, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QPainter
from PySide6.QtWidgets import (
    QAbstractItemView, QFrame, QHBoxLayout, QLineEdit, QListView, QStyle, QStyledItemDelegate, QVBoxLayout, QWidget,
)

from tenable_net.gui import icons, theme
from tenable_net.gui.widgets import Kbd, label

GROUP_LIMIT = 6     # results shown per group while typing
TOTAL_LIMIT = 60


@dataclass
class Entry:
    title: str
    group: str = ""
    icon: str = "arrow-right"
    subtitle: str = ""
    keys: tuple = ()            # shortcut shown as key caps, e.g. ("Ctrl", "P")
    run: Callable = None
    header: bool = False
    haystack: str = field(default="", repr=False)

    def __post_init__(self):
        self.haystack = f"{self.title} {self.subtitle} {self.group}".lower()


def shortcut_keys(sequence):
    """('Ctrl', 'Shift', 'E') from a QKeySequence."""
    from PySide6.QtGui import QKeySequence

    text = sequence.toString(QKeySequence.NativeText) if sequence and not sequence.isEmpty() else ""
    return tuple(part for part in text.split("+") if part) if text else ()


def rank(entries, query):
    """Entries whose text contains every word of the query; prefix matches first, then shorter titles."""
    words = query.lower().split()
    if not words:
        return entries
    hits = [e for e in entries if all(w in e.haystack for w in words)]
    first = words[0]
    return sorted(hits, key=lambda e: (not e.title.lower().startswith(first), first not in e.title.lower(),
                                       len(e.title)))


class PaletteModel(QAbstractListModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.rows = []

    def set_rows(self, rows):
        self.beginResetModel()
        self.rows = rows
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        entry = self.rows[index.row()]
        if role == Qt.DisplayRole:
            return entry.title
        if role == Qt.UserRole:
            return entry
        return None

    def flags(self, index):
        if index.isValid() and self.rows[index.row()].header:
            return Qt.NoItemFlags
        return Qt.ItemIsEnabled | Qt.ItemIsSelectable


class PaletteDelegate(QStyledItemDelegate):
    def sizeHint(self, option, index):
        entry = index.data(Qt.UserRole)
        return QSize(option.rect.width(), 30 if entry.header else 38)

    def paint(self, painter, option, index):
        entry = index.data(Qt.UserRole)
        t = theme.tokens()
        r = QRectF(option.rect)
        painter.save()
        painter.setRenderHint(QPainter.Antialiasing)
        if entry.header:
            painter.setFont(theme.font("caption", weight="medium"))
            painter.setPen(QColor(t["text_muted"]))
            painter.drawText(r.adjusted(18, 8, -18, 0), Qt.AlignLeft | Qt.AlignVCenter, entry.title)
            painter.restore()
            return
        if option.state & QStyle.State_Selected:
            painter.setPen(Qt.NoPen)
            painter.setBrush(QColor(t["raised_hover"]))
            painter.drawRoundedRect(r.adjusted(6, 1, -6, -1), 6, 6)
        icons.paint(painter, entry.icon, QRectF(r.left() + 18, r.center().y() - 8, 16, 16),
                    t["text"] if option.state & QStyle.State_Selected else t["text_muted"])
        body = theme.font("body")
        painter.setFont(body)
        fm = painter.fontMetrics()
        right = r.right() - 18
        if entry.keys:  # key caps on the right
            cap_font = theme.font("caption", weight="medium")
            painter.setFont(cap_font)
            cfm = painter.fontMetrics()
            x = right
            for key in reversed(entry.keys):
                w = max(cfm.horizontalAdvance(key) + 10, 20)
                cap = QRectF(x - w, r.center().y() - 10, w, 20)
                painter.setPen(QColor(t["kbd_border"]))
                painter.setBrush(QColor(t["kbd_bg"]))
                painter.drawRoundedRect(cap.adjusted(0.5, 0.5, -0.5, -0.5), 4, 4)
                painter.setPen(QColor(t["kbd_text"]))
                painter.drawText(cap, Qt.AlignCenter, key)
                x -= w + 4
            right = x - 8
            painter.setFont(body)
        elif entry.subtitle:
            painter.setFont(theme.font("caption"))
            sub = painter.fontMetrics()
            text = sub.elidedText(entry.subtitle, Qt.ElideLeft, int(min(260, (right - r.left()) / 2)))
            w = sub.horizontalAdvance(text)
            painter.setPen(QColor(t["text_faint"]))
            painter.drawText(QRectF(right - w, r.top(), w, r.height()), Qt.AlignVCenter | Qt.AlignRight, text)
            right -= w + 12
            painter.setFont(body)
        left = r.left() + 46
        painter.setPen(QColor(t["text"]))
        painter.drawText(QRectF(left, r.top(), max(right - left, 0), r.height()), Qt.AlignVCenter | Qt.AlignLeft,
                         fm.elidedText(entry.title, Qt.ElideRight, int(max(right - left, 0))))
        painter.restore()


class PaletteInput(QLineEdit):
    """The palette's search box. Keys that drive the list are turned into signals here, rather than with an
    event filter: Python event filters can be called while widgets are being torn down, which crashes."""

    moved = Signal(int)      # +1 / -1 / ±8 rows
    accepted = Signal()
    dismissed = Signal()

    def keyPressEvent(self, event):
        steps = {Qt.Key_Down: 1, Qt.Key_Tab: 1, Qt.Key_Up: -1, Qt.Key_Backtab: -1, Qt.Key_PageDown: 8,
                 Qt.Key_PageUp: -8}
        if event.key() in steps:
            self.moved.emit(steps[event.key()])
        elif event.key() in (Qt.Key_Return, Qt.Key_Enter):
            self.accepted.emit()
        elif event.key() == Qt.Key_Escape:
            self.dismissed.emit()
        else:
            super().keyPressEvent(event)

    def focusNextPrevChild(self, _next):
        return False  # keep Tab for moving through results


class CommandPalette(QWidget):
    """A dimmed overlay over its parent window with the palette panel near the top."""

    def __init__(self, window, fallback=None):
        """fallback(text): what Enter does when nothing matches (e.g. search the findings)."""
        super().__init__(window)
        self.setObjectName("PaletteScrim")
        self.setAttribute(Qt.WA_StyledBackground, True)
        self.fallback = fallback
        self.search_findings = True
        self.entries = []
        self._return_focus = None

        self.panel = QFrame(self)
        self.panel.setObjectName("PalettePanel")
        layout = QVBoxLayout(self.panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        self.input = PaletteInput()
        self.input.setObjectName("PaletteInput")
        self.input.setPlaceholderText("Type a command, or search devices, CVEs, plugins, models, serials…")
        theme.set_font(self.input, "title", weight="regular")
        self.input.textChanged.connect(self.refilter)
        self.input.moved.connect(self.move_selection)
        self.input.accepted.connect(lambda: self.activate(self.list.currentIndex()))
        self.input.dismissed.connect(self.close_palette)
        self.model = PaletteModel(self)
        self.list = QListView()
        self.list.setObjectName("PaletteList")
        self.list.setModel(self.model)
        self.list.setItemDelegate(PaletteDelegate(self.list))
        self.list.setUniformItemSizes(False)
        self.list.setMouseTracking(True)
        self.list.setFocusPolicy(Qt.NoFocus)
        self.list.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.list.entered.connect(self._hover)
        self.list.clicked.connect(self.activate)
        footer = QFrame()
        footer.setObjectName("PaletteFooter")
        fl = QHBoxLayout(footer)
        fl.setContentsMargins(16, 8, 16, 8)
        fl.setSpacing(6)
        for keys, text in ((("↑", "↓"), "to navigate"), (("↵",), "to open"), (("Esc",), "to close")):
            for key in keys:
                fl.addWidget(Kbd(key))
            fl.addWidget(label(text, "caption", "Muted"))
            fl.addSpacing(10)
        fl.addStretch(1)
        self.count = label("", "caption", "Faint")
        fl.addWidget(self.count)
        layout.addWidget(self.input)
        layout.addWidget(self.list, 1)
        layout.addWidget(footer)
        self.hide()

    # ---- open / close ----------------------------------------------------------------------
    def open(self, entries, text="", search_findings=True):
        """entries: [Entry]; commands first, then search targets. search_findings: offer (and fall back to)
        searching the findings for the typed text."""
        self.entries = entries
        self.search_findings = search_findings
        self._return_focus = self.window().focusWidget()
        self.place()
        self.input.blockSignals(True)
        self.input.setText(text)
        self.input.blockSignals(False)
        self.refilter()
        self.show()
        self.raise_()
        self.input.setFocus()
        self.input.selectAll()

    def close_palette(self):
        self.hide()
        if self._return_focus is not None:
            try:
                self._return_focus.setFocus()
            except RuntimeError:  # widget gone
                pass
        self._return_focus = None

    def place(self):
        """Cover the parent window; the owner calls this again when the window is resized."""
        window = self.parentWidget()
        self.setGeometry(window.rect())
        width = min(660, window.width() - 64)
        height = min(470, window.height() - 120)
        self.panel.setGeometry((window.width() - width) // 2, max(48, round(window.height() * 0.13)), width, height)

    def mousePressEvent(self, event):
        if not self.panel.geometry().contains(event.position().toPoint()):
            self.close_palette()
            return
        super().mousePressEvent(event)

    # ---- results ----------------------------------------------------------------------------
    def refilter(self, *_):
        query = self.input.text().strip()
        rows = []
        if query:
            if self.fallback is not None and self.search_findings:
                rows.append(Entry(f"Search findings for “{query}”", "Search", "search", "Findings",
                                  run=lambda q=query: self.fallback(q)))
            groups = {}
            for entry in rank(self.entries, query):
                bucket = groups.setdefault(entry.group, [])
                if len(bucket) < (GROUP_LIMIT * 2 if entry.group == "Commands" else GROUP_LIMIT):
                    bucket.append(entry)
            if rows:
                rows.insert(0, Entry("Search", header=True))
            for group, hits in groups.items():
                rows.append(Entry(group, header=True))
                rows.extend(hits)
                if len(rows) > TOTAL_LIMIT:
                    break
        else:
            group = None
            for entry in self.entries:
                if entry.group != "Commands" and entry.group != "Go to":
                    continue
                if entry.group != group:
                    rows.append(Entry(entry.group, header=True))
                    group = entry.group
                rows.append(entry)
        self.model.set_rows(rows)
        hits = sum(1 for r in rows if not r.header)
        self.count.setText(f"{hits} result{'s' if hits != 1 else ''}" if query else "")
        self._select_first()

    def _select_first(self):
        for row, entry in enumerate(self.model.rows):
            if not entry.header:
                self.list.setCurrentIndex(self.model.index(row))
                return

    def move_selection(self, step):
        rows = self.model.rows
        if not rows:
            return
        row = self.list.currentIndex().row()
        direction = 1 if step > 0 else -1
        target = row
        remaining = abs(step)
        while remaining:
            nxt = target + direction
            while 0 <= nxt < len(rows) and rows[nxt].header:
                nxt += direction
            if not 0 <= nxt < len(rows):
                break
            target = nxt
            remaining -= 1
        if target != row and target >= 0:
            index = self.model.index(target)
            self.list.setCurrentIndex(index)
            self.list.scrollTo(index)

    def _hover(self, index):
        if index.isValid() and not self.model.rows[index.row()].header:
            self.list.setCurrentIndex(index)

    def activate(self, index):
        if not index.isValid():
            text = self.input.text().strip()
            if text and self.fallback is not None and self.search_findings:
                self.close_palette()
                QTimer.singleShot(0, lambda: self.fallback(text))
            return
        entry = self.model.rows[index.row()]
        if entry.header or entry.run is None:
            return
        self.close_palette()
        QTimer.singleShot(0, entry.run)  # let the overlay disappear before a heavy jump
