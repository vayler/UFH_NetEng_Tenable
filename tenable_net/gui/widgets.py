"""Shared widgets: tables and their cell painters, stat tiles, panels, chips, toast, detail pane, worker."""

import html
import traceback

import pandas as pd
from PySide6.QtCore import (
    QEasingCurve, QObject, QPointF, QPropertyAnimation, QRectF, QSize, Qt, QThread, QTimer, Signal,
)
from PySide6.QtGui import QColor, QIcon, QLinearGradient, QPainter, QPainterPath, QPalette, QPen, QPixmap
from PySide6.QtWidgets import (
    QAbstractItemView, QButtonGroup, QFrame, QGraphicsOpacityEffect, QHBoxLayout, QHeaderView, QLabel, QLineEdit,
    QMenu, QPushButton, QSizePolicy, QSplitter, QStackedWidget, QStyle, QStyledItemDelegate,
    QStyleOptionViewItem, QTableView, QTextBrowser, QToolButton, QVBoxLayout, QWidget, QWidgetAction,
)

from tenable_net import glossary
from tenable_net.gui import icons, theme
from tenable_net.gui.models import RAW_ROLE, display, is_true
from tenable_net.gui.theme import SEVERITY_COLORS, SEVERITY_TEXT, severity_color  # noqa: F401 (re-exported)

PAD = 10  # horizontal cell padding
STATUS_COLUMNS = ("contract", "sw_status", "lifecycle", "change", "confidence")


def severity_icon(severity, size=14):
    pm = QPixmap(size * 2, size * 2)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    p.scale(2, 2)
    paint_severity_mark(p, severity, QRectF(0, 0, size, size))
    p.end()
    pm.setDevicePixelRatio(2)
    return QIcon(pm)


def paint_severity_mark(painter, severity, rect):
    """Critical: a filled square with '!'. High / medium / low / info: three signal bars, 3 / 2 / 1 / 0 lit."""
    sev = str(severity)
    hue = QColor(SEVERITY_COLORS.get(sev, SEVERITY_COLORS["info"]))
    painter.save()
    painter.setRenderHint(QPainter.Antialiasing)
    painter.setPen(Qt.NoPen)
    if sev == "critical":
        box = QRectF(rect).adjusted(0.5, 0.5, -0.5, -0.5)
        painter.setBrush(hue)
        painter.drawRoundedRect(box, 3.2, 3.2)
        pen = QPen(QColor("#FFFFFF"), max(box.width() * 0.13, 1.5))
        pen.setCapStyle(Qt.RoundCap)
        painter.setPen(pen)
        cx = box.center().x()
        painter.drawLine(QPointF(cx, box.top() + box.height() * 0.24), QPointF(cx, box.top() + box.height() * 0.58))
        painter.drawPoint(QPointF(cx, box.top() + box.height() * 0.78))
    else:
        lit = {"high": 3, "medium": 2, "low": 1}.get(sev, 0)
        dim = QColor(theme.tokens()["border_strong"])
        w = rect.width() / 5.2
        gap = w * 0.6
        x = rect.left() + (rect.width() - (3 * w + 2 * gap)) / 2
        for i in range(3):
            h = rect.height() * (0.42 + 0.29 * i)
            bar = QRectF(x + i * (w + gap), rect.bottom() - h - rect.height() * 0.06, w, h)
            painter.setBrush(hue if i < lit else dim)
            painter.drawRoundedRect(bar, w / 2.6, w / 2.6)
    painter.restore()


# ---- tables ------------------------------------------------------------------------------

class Table(QTableView):
    """QTableView that tracks the hovered row so delegates can tint the whole row."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.hover_row = -1
        self.setMouseTracking(True)

    def _set_hover(self, row):
        if row != self.hover_row:
            self.hover_row = row
            self.viewport().update()

    def mouseMoveEvent(self, event):
        self._set_hover(self.rowAt(round(event.position().y())))
        super().mouseMoveEvent(event)

    def leaveEvent(self, event):
        self._set_hover(-1)
        super().leaveEvent(event)

    def wheelEvent(self, event):
        super().wheelEvent(event)
        self._set_hover(self.rowAt(round(event.position().y())))


class RowDelegate(QStyledItemDelegate):
    """Paints a cell: row hover / selection background, a hairline under the row, then elided text."""

    def _option(self, option, index):
        opt = QStyleOptionViewItem(option)
        self.initStyleOption(opt, index)
        return opt

    def paint_row(self, painter, option, index):
        t = theme.tokens()
        view = option.widget
        selected = bool(option.state & QStyle.State_Selected)
        if selected:
            painter.fillRect(option.rect, QColor(t["selection"]))
        elif view is not None and getattr(view, "hover_row", -1) == index.row():
            painter.fillRect(option.rect, QColor(t["row_hover"]))
        painter.fillRect(QRectF(option.rect.left(), option.rect.bottom(), option.rect.width(), 1), QColor(t["divider"]))

    def text_color(self, index):
        fg = index.data(Qt.ForegroundRole)
        if fg is not None:
            return fg.color() if hasattr(fg, "color") else QColor(fg)
        return QColor(theme.tokens()["text"])

    def draw_text(self, painter, option, rect, text, color=None, align=None):
        if not text:
            return
        painter.setFont(option.font)
        painter.setPen(color or QColor(theme.tokens()["text"]))
        elided = option.fontMetrics.elidedText(str(text), Qt.ElideRight, max(int(rect.width()), 0))
        painter.drawText(rect, int(align or (Qt.AlignLeft | Qt.AlignVCenter)), elided)

    def paint(self, painter, option, index):
        opt = self._option(option, index)
        painter.save()
        self.paint_row(painter, opt, index)
        align = index.data(Qt.TextAlignmentRole) or (Qt.AlignLeft | Qt.AlignVCenter)
        self.draw_text(painter, opt, QRectF(opt.rect).adjusted(PAD, 0, -PAD, 0), opt.text, self.text_color(index),
                       align)
        painter.restore()

    def content_width(self, option, index):
        return option.fontMetrics.horizontalAdvance(str(index.data(Qt.DisplayRole) or ""))

    def sizeHint(self, option, index):
        opt = self._option(option, index)
        return QSize(self.content_width(opt, index) + 2 * PAD + 2, theme.row_height())


class SeverityDelegate(RowDelegate):
    """Severity as a small signal-bar mark (filled square for critical) beside the word."""

    def paint(self, painter, option, index):
        sev = str(index.data(RAW_ROLE) or "")
        if sev not in SEVERITY_COLORS:
            return super().paint(painter, option, index)
        opt = self._option(option, index)
        painter.save()
        self.paint_row(painter, opt, index)
        r = QRectF(opt.rect)
        size = round(opt.fontMetrics.height() * 0.9)
        paint_severity_mark(painter, sev, QRectF(r.left() + PAD, r.center().y() - size / 2, size, size))
        self.draw_text(painter, opt, r.adjusted(PAD + size + 8, 0, -PAD, 0), sev.title())
        painter.restore()

    def content_width(self, option, index):
        fm = option.fontMetrics
        return max(fm.horizontalAdvance(w) for w in ("Critical", "Medium")) + fm.height() + 10


class RiskDelegate(RowDelegate):
    """Risk score as a progress ring in its band colour, then the number."""

    def paint(self, painter, option, index):
        try:
            score = float(index.data(RAW_ROLE))
        except (TypeError, ValueError):
            return super().paint(painter, option, index)
        if score != score:  # NaN
            return super().paint(painter, option, index)
        from tenable_net.risk import band

        opt = self._option(option, index)
        painter.save()
        self.paint_row(painter, opt, index)
        r = QRectF(opt.rect)
        size = round(opt.fontMetrics.height() * 0.95)
        ring = QRectF(r.left() + PAD, r.center().y() - size / 2, size, size)
        paint_ring(painter, ring, score, theme.band_color(band(score)))
        number = QRectF(ring.right() + 4, r.top(), opt.fontMetrics.horizontalAdvance("100") + 2, r.height())
        self.draw_text(painter, opt, number, f"{score:.0f}", align=Qt.AlignRight | Qt.AlignVCenter)
        painter.restore()

    def content_width(self, option, index):
        return option.fontMetrics.height() + 6 + option.fontMetrics.horizontalAdvance("100")


def paint_ring(painter, rect, score, hue):
    painter.save()
    painter.setRenderHint(QPainter.Antialiasing)
    track = QColor(hue)
    track.setAlphaF(0.30)
    pen = QPen(track, max(rect.width() * 0.12, 1.4))
    painter.setPen(pen)
    painter.setBrush(Qt.NoBrush)
    painter.drawEllipse(rect.adjusted(1, 1, -1, -1))
    pen.setColor(QColor(hue))
    painter.setPen(pen)
    span = -int(360 * 16 * max(0.0, min(score, 100.0)) / 100.0)
    painter.drawArc(rect.adjusted(1, 1, -1, -1), 90 * 16, span)
    inner = rect.adjusted(rect.width() * 0.3, rect.height() * 0.3, -rect.width() * 0.3, -rect.height() * 0.3)
    painter.setPen(Qt.NoPen)
    painter.setBrush(QColor(hue))
    painter.drawPie(inner, 90 * 16, span)
    painter.restore()


class StatusDelegate(RowDelegate):
    """A status word with a coloured dot (Covered, Not covered, Upgrade suggested, New, Confirmed…)."""

    def __init__(self, parent=None, band=False, default_token=None):
        super().__init__(parent)
        self.band = band
        self.default_token = default_token

    def dot(self, value):
        if not value or value == "All devices":
            return None
        if self.band:
            return theme.band_color(value)
        return theme.status_dot(value) or (theme.tokens()[self.default_token] if self.default_token else None)

    def paint(self, painter, option, index):
        value = str(index.data(Qt.DisplayRole) or "")
        dot = self.dot(value)
        if not dot:
            return super().paint(painter, option, index)
        opt = self._option(option, index)
        painter.save()
        self.paint_row(painter, opt, index)
        r = QRectF(opt.rect)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(dot))
        painter.drawEllipse(QPointF(r.left() + PAD + 3.5, r.center().y() + 0.5), 3.5, 3.5)
        self.draw_text(painter, opt, r.adjusted(PAD + 14, 0, -PAD, 0), value)
        painter.restore()

    def content_width(self, option, index):
        return super().content_width(option, index) + 14


def make_table(model, stretch_column=None):
    """A sortable, read-only, row-selecting table with hover rows and the app's cell painters."""
    view = Table()
    view.setModel(model)
    view.setSortingEnabled(True)
    view.setSelectionBehavior(QAbstractItemView.SelectRows)
    view.setSelectionMode(QAbstractItemView.SingleSelection)
    view.setEditTriggers(QAbstractItemView.NoEditTriggers)
    view.setAlternatingRowColors(False)
    view.setShowGrid(False)
    view.setWordWrap(False)
    view.setFrameShape(QFrame.NoFrame)
    view.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
    view.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
    view.setFont(theme.table_font())
    view.verticalHeader().setVisible(False)
    view.verticalHeader().setDefaultSectionSize(theme.row_height())
    header = view.horizontalHeader()
    theme.set_font(header, "caption", weight="medium")
    header.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
    header.setResizeContentsPrecision(150)  # size columns from a sample, not every row
    header.setHighlightSections(False)
    header.setSectionResizeMode(QHeaderView.Interactive)
    header.setStretchLastSection(stretch_column is None)
    header.setMinimumHeight(32)
    view.setItemDelegate(RowDelegate(view))
    view._severity_delegate = SeverityDelegate(view)
    view._risk_delegate = RiskDelegate(view)
    view._status_delegate = StatusDelegate(view)
    view._band_delegate = StatusDelegate(view, band=True)
    view._stage_delegate = StatusDelegate(view, default_token="dot_bad")
    view._stretch_column = stretch_column
    return view


def fit_columns(view, max_width=360, caps=None):
    """Size columns to content (sampled), apply the cell painters and the stretch column.

    caps: optional {column: max width} overriding max_width for specific columns."""
    caps = caps or {}
    source = view.model()
    while hasattr(source, "sourceModel"):
        source = source.sourceModel()
    columns = getattr(source, "columns", [])
    header = view.horizontalHeader()
    header.setSectionResizeMode(QHeaderView.Interactive)  # clear a stretch left from a previous column set
    delegates = {"severity": view._severity_delegate, "risk": view._risk_delegate,
                 "risk_band": view._band_delegate, "stage": view._stage_delegate}
    for i, col in enumerate(columns):
        delegate = delegates.get(col) or (view._status_delegate if col in STATUS_COLUMNS else None)
        view.setItemDelegateForColumn(i, delegate)  # None restores the default painter
        view.resizeColumnToContents(i)
        if view.columnWidth(i) > caps.get(col, max_width):
            view.setColumnWidth(i, caps.get(col, max_width))
        if col == view._stretch_column:
            header.setSectionResizeMode(i, QHeaderView.Stretch)


# ---- small building blocks -------------------------------------------------------------------

class PageStack(QStackedWidget):
    """A stacked widget sized by the page showing, not the largest page, so one wide view doesn't set the
    whole window's minimum width."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.currentChanged.connect(lambda _i: self.updateGeometry())

    def sizeHint(self):
        page = self.currentWidget()
        return page.sizeHint() if page is not None else super().sizeHint()

    def minimumSizeHint(self):
        page = self.currentWidget()
        return page.minimumSizeHint() if page is not None else super().minimumSizeHint()


def _tint_button(b):
    if not b.property("icon_name"):
        return
    t = theme.tokens()
    color = t["on_accent"] if b.objectName() == "Primary" else (
        t["text_muted"] if b.property("variant") == "ghost" else t["text"])
    b.setIcon(icons.icon(b.property("icon_name"), color))
    b.setIconSize(QSize(15, 15))


class Button(QPushButton):
    """QPushButton whose icon re-tints when the theme changes, with a little more room between icon and text
    than Qt's built-in 4 px."""

    def __init__(self, text="", parent=None):
        super().__init__(text, parent)
        theme.signals.changed.connect(self.retheme)  # bound method: disconnected when the button goes

    def retheme(self, *_):
        _tint_button(self)

    def setText(self, text):
        super().setText(("\u2009" + text) if self.property("icon_name") and text else text)


def button(text="", variant=None, icon_name=None, tooltip=None, parent=None):
    """Push button in a style variant: None (secondary), 'primary', 'ghost' or 'link'."""
    b = Button(text, parent)
    if variant == "primary":
        b.setObjectName("Primary")
    elif variant:
        b.setProperty("variant", variant)
    if icon_name:
        b.setProperty("icon_name", icon_name)
        _tint_button(b)
        b.setText(text)  # re-applied so the icon gets its gap
    if tooltip:
        b.setToolTip(tooltip)
    b.setCursor(Qt.PointingHandCursor)
    return b


class IconButton(QToolButton):
    """Square ghost button with a single icon."""

    def __init__(self, icon_name, tooltip="", parent=None, size=28):
        super().__init__(parent)
        self.icon_name = icon_name
        self.setToolTip(tooltip)
        self.setFixedSize(size, size)
        self.setIconSize(QSize(16, 16))
        self.setCursor(Qt.PointingHandCursor)
        self.retheme()
        theme.signals.changed.connect(self.retheme)

    def retheme(self, *_):
        t = theme.tokens()
        self.setIcon(icons.icon(self.icon_name, t["text_muted"], active_color=t["text"]))


class MenuButton(Button):
    """Push button that opens a menu: the text, then a chevron on the right (the chevron is the button's icon,
    placed after the text by a right-to-left layout)."""

    def __init__(self, text="", variant=None, parent=None):
        super().__init__(text, parent)
        if variant:
            self.setProperty("variant", variant)
        self.setLayoutDirection(Qt.RightToLeft)
        self.setIconSize(QSize(14, 14))
        self.setCursor(Qt.PointingHandCursor)
        self.retheme()

    def retheme(self, *_):
        t = theme.tokens()
        color = t["accent_text"] if self.property("active") else t["text_muted"]
        self.setIcon(icons.icon("chevron-down", color, 14))

    def setMenu(self, menu):
        menu.setLayoutDirection(Qt.LeftToRight)  # the button is right-to-left only to put the chevron last
        super().setMenu(menu)


class FilterChip(MenuButton):
    """Filter control in the Linear style: reads 'Severity' when unset and 'Severity: Critical, High' when
    filtering. Clicking opens a popup holding the chip's own controls (checkboxes, fields)."""

    def __init__(self, label, parent=None):
        super().__init__(label, parent=parent)
        self.label = label
        self.setProperty("chip", True)
        self.popup = QMenu(self)
        self.content = QWidget()
        self.content_layout = QVBoxLayout(self.content)
        self.content_layout.setContentsMargins(10, 8, 12, 8)
        self.content_layout.setSpacing(8)
        action = QWidgetAction(self.popup)
        action.setDefaultWidget(self.content)
        self.popup.addAction(action)
        self.setMenu(self.popup)

    def set_summary(self, summary=None):
        active = bool(summary)
        self.setText(f"{self.label}: {summary}" if active else self.label)
        if bool(self.property("active")) != active:
            self.setProperty("active", active)
            theme.repolish(self)
            self.retheme()


class ToggleChip(QPushButton):
    """A checkable quick filter (e.g. 'Exploitable'): dashed when off, accent-tinted when on."""

    def __init__(self, text, icon_name=None, tooltip=None, parent=None):
        super().__init__(text, parent)
        self.setCheckable(True)
        self.setProperty("chip", True)
        self.icon_name = icon_name
        if tooltip:
            self.setToolTip(tooltip)
        self.setCursor(Qt.PointingHandCursor)
        self.toggled.connect(self.retheme)
        theme.signals.changed.connect(self.retheme)
        self.retheme()

    def retheme(self, *_):
        if self.icon_name:
            t = theme.tokens()
            self.setIcon(icons.icon(self.icon_name, t["accent_text"] if self.isChecked() else t["text_muted"]))
            self.setIconSize(QSize(14, 14))


class Segmented(QFrame):
    """Segmented control (e.g. 30 days | 90 days | All). Mirrors the QComboBox calls views already use."""

    currentIndexChanged = Signal(int)

    def __init__(self, options, current=None, parent=None):
        super().__init__(parent)
        self.setObjectName("Segmented")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(2, 2, 2, 2)
        layout.setSpacing(2)
        self.group = QButtonGroup(self)
        self.group.setExclusive(True)
        for i, text in enumerate(options):
            b = QPushButton(text)
            b.setCheckable(True)
            b.setProperty("segment", True)
            b.setCursor(Qt.PointingHandCursor)
            self.group.addButton(b, i)
            layout.addWidget(b)
        self.group.button(options.index(current) if current in options else 0).setChecked(True)
        self.group.idToggled.connect(lambda i, on: on and self.currentIndexChanged.emit(i))

    def currentIndex(self):
        return self.group.checkedId()

    def currentText(self):
        b = self.group.checkedButton()
        return b.text() if b else ""

    def setCurrentIndex(self, i):
        self.group.button(i).setChecked(True)

    def setCurrentText(self, text):
        for b in self.group.buttons():
            if b.text() == text:
                b.setChecked(True)


class SearchField(QLineEdit):
    """Line edit with a leading search icon."""

    def __init__(self, placeholder="Search…", parent=None):
        super().__init__(parent)
        self.setPlaceholderText(placeholder)
        self.setClearButtonEnabled(True)
        self._icon_action = self.addAction(QIcon(), QLineEdit.LeadingPosition)
        self.retheme()
        theme.signals.changed.connect(self.retheme)

    def retheme(self, *_):
        self._icon_action.setIcon(icons.icon("search", theme.tokens()["text_faint"], 15))


class Splitter(QSplitter):
    """A splitter drawn as a hairline. Qt paints a 1 px handle but keeps a 5 px grab area around it ("tiny
    mode"); the stylesheet colours it. Deliberately no Python QSplitterHandle subclass: a handle created in
    Python and handed to Qt through createHandle() lets PySide free the splitter's widgets when the garbage
    collector runs."""

    def __init__(self, orientation, line=True, parent=None):
        super().__init__(orientation, parent)
        self.setProperty("line", bool(line))
        self.setHandleWidth(1 if line else 6)
        self.setChildrenCollapsible(False)


class Kbd(QLabel):
    """A keyboard key, e.g. Ctrl or K."""

    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setObjectName("Kbd")
        theme.set_font(self, "caption", weight="medium")
        self.setAlignment(Qt.AlignCenter)
        self.setMinimumWidth(18)


class ElidedLabel(QLabel):
    """Single-line plain-text label that shrinks with an ellipsis instead of widening its parent."""

    def __init__(self, text="", parent=None):
        super().__init__(text, parent)
        self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred)

    def minimumSizeHint(self):
        return QSize(0, super().minimumSizeHint().height())

    def paintEvent(self, _event):
        p = QPainter(self)
        p.setFont(self.font())
        p.setPen(self.palette().color(QPalette.WindowText))
        rect = self.contentsRect()
        text = self.fontMetrics().elidedText(self.text(), Qt.ElideRight, rect.width())
        p.drawText(rect, int(self.alignment()), text)
        p.end()


def elided(text="", role="body", object_name=None, weight=None):
    w = ElidedLabel(text)
    theme.set_font(w, role, weight=weight)
    if object_name:
        w.setObjectName(object_name)
    return w


def label(text="", role="body", object_name=None, bold=False, weight=None, wrap=False):
    w = QLabel(text)
    theme.set_font(w, role, bold, weight)
    if object_name:
        w.setObjectName(object_name)
    if wrap:
        w.setWordWrap(True)
    return w


def divider(vertical=False):
    line = QFrame()
    line.setObjectName("Divider")
    if vertical:
        line.setFixedWidth(1)
    else:
        line.setFixedHeight(1)
    return line


class Panel(QFrame):
    """A bordered section with a header row (title, muted note, actions on the right) and a body."""

    def __init__(self, title="", body=None, subtitle=None, flush=False, parent=None):
        super().__init__(parent)
        self.setObjectName("Panel")
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        head = QHBoxLayout()
        head.setContentsMargins(16, 12, 12, 8)
        head.setSpacing(8)
        self.title = label(title, "section", "PanelTitle")
        self.subtitle = elided(subtitle or "", "caption", "Muted")
        self.subtitle.setVisible(bool(subtitle))
        head.addWidget(self.title)
        head.addWidget(self.subtitle)
        head.addStretch(1)
        self.actions = head
        outer.addLayout(head)
        self.body = QVBoxLayout()
        self.body.setContentsMargins(6, 0, 6, 6) if flush else self.body.setContentsMargins(16, 4, 16, 14)
        self.body.setSpacing(8)
        outer.addLayout(self.body, 1)
        if body is not None:
            self.body.addWidget(body, 1)

    def add_action(self, widget):
        self.actions.addWidget(widget)
        return widget

    def set_subtitle(self, text):
        self.subtitle.setText(text)
        self.subtitle.setVisible(bool(text))


class Sparkline(QWidget):
    """Tiny line chart of recent values (e.g. criticals per pull) with a soft fill underneath."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.values = []
        self.color = theme.color("accent")
        self.setFixedHeight(26)

    def set_values(self, values, color=None):
        self.values = [float(v) for v in values if v is not None]
        if color is not None:
            self.color = QColor(color)
        self.setVisible(len(self.values) >= 2)
        self.update()

    def paintEvent(self, _event):
        if len(self.values) < 2:
            return
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        lo, hi = min(self.values), max(self.values)
        span = (hi - lo) or 1.0
        w, h = self.width() - 6, self.height() - 6
        step = w / (len(self.values) - 1)
        points = [QPointF(3 + i * step, 3 + h - (v - lo) / span * h) for i, v in enumerate(self.values)]
        line = QPainterPath(points[0])
        for pt in points[1:]:
            line.lineTo(pt)
        area = QPainterPath(line)
        area.lineTo(points[-1].x(), self.height())
        area.lineTo(points[0].x(), self.height())
        area.closeSubpath()
        grad = QLinearGradient(0, 0, 0, self.height())
        top, bottom = QColor(self.color), QColor(self.color)
        top.setAlphaF(0.18)
        bottom.setAlphaF(0.0)
        grad.setColorAt(0, top)
        grad.setColorAt(1, bottom)
        p.fillPath(area, grad)
        pen = QPen(self.color, 1.6)
        pen.setJoinStyle(Qt.RoundJoin)
        p.setPen(pen)
        p.drawPath(line)
        p.setPen(QPen(QColor(theme.tokens()["surface"]), 1.5))
        p.setBrush(self.color)
        p.drawEllipse(points[-1], 2.8, 2.8)
        p.end()


class KpiCard(QFrame):
    """Headline number: caption (with an optional colour dot), value, change vs. the previous pull and a
    sparkline. Tiles sit side by side in a StatStrip; colour only appears in the dot and the trend. Clickable."""

    clicked = Signal()

    def __init__(self, caption, accent=None, term=None, higher_is_bad=True, parent=None):
        super().__init__(parent)
        self.setObjectName("StatTile")
        self.accent = accent
        self.higher_is_bad = higher_is_bad
        self.setCursor(Qt.PointingHandCursor)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 10)
        layout.setSpacing(2)
        self.caption = elided("", "caption", "StatCaption", weight="medium")
        self.dot = QLabel()
        self.dot.setTextFormat(Qt.RichText)
        self.dot.setVisible(bool(accent))
        theme.set_font(self.dot, "caption")
        self._caption_text = caption
        self.value = label("–", "kpi")
        self.delta = label("", "caption", "Muted")
        self.delta.setTextFormat(Qt.RichText)
        self.spark = Sparkline()
        self.spark.setVisible(False)
        caption_row = QHBoxLayout()
        caption_row.setSpacing(5)
        caption_row.addWidget(self.dot)
        caption_row.addWidget(self.caption, 1)
        layout.addLayout(caption_row)
        layout.addSpacing(2)
        layout.addWidget(self.value)
        layout.addWidget(self.delta)
        layout.addStretch(1)
        layout.addWidget(self.spark)
        self._render_caption()
        tip = glossary.TERMS.get(term) if term else None
        if tip:
            self.setToolTip(f"<b>{term}</b><br>{tip}")

    def _render_caption(self):
        if self.accent:
            self.dot.setText(f"<span style='color:{self.accent}'>●</span>")
        self.caption.setText(self._caption_text)

    def set_value(self, value):
        self.value.setText(value if isinstance(value, str) else f"{value:,}")

    def set_delta(self, change, suffix="since last pull"):
        """change: number vs. the previous pull (None hides it). Red when it moved the bad way."""
        if change is None:
            self.delta.setText("")
            return
        t = theme.tokens()
        if change == 0:
            self.delta.setText(f"<span style='color:{t['text_muted']}'>No change {suffix}</span>")
            return
        worse = (change > 0) == self.higher_is_bad
        arrow = "▲" if change > 0 else "▼"
        color = t["bad" if worse else "good"]
        self.delta.setText(f"<span style='color:{color}; font-weight:500'>{arrow} {abs(change):,}</span>"
                           f"<span style='color:{t['text_muted']}'>&nbsp; {suffix}</span>")

    def set_trend(self, values):
        self.spark.set_values(values, self.accent or theme.tokens()["accent"])

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.LeftButton and self.rect().contains(event.position().toPoint()):
            self.clicked.emit()
        super().mouseReleaseEvent(event)


class StatStrip(QFrame):
    """One bordered panel holding stat tiles side by side, separated by hairlines."""

    def __init__(self, tiles, parent=None):
        super().__init__(parent)
        self.setObjectName("Panel")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)
        for i, tile in enumerate(tiles):
            if i:
                layout.addWidget(divider(vertical=True))
            layout.addWidget(tile, 1)


class Chip(QWidget):
    """Sidebar status row: a coloured dot, a label and optional muted detail on the right. Emits clicked."""

    clicked = Signal()

    def __init__(self, text="", status="neutral", parent=None):
        super().__init__(parent)
        self.status = status
        self.plain_text = text
        self.detail = ""
        self.setFixedHeight(28)
        self.setCursor(Qt.PointingHandCursor)
        self.setAttribute(Qt.WA_Hover)
        self.set(text, status)

    def set(self, text, status="neutral", tooltip=None, detail=""):
        self.status, self.plain_text, self.detail = status, text, detail
        if tooltip:
            self.setToolTip(tooltip)
        self.update()

    def text(self):
        return self.plain_text

    def enterEvent(self, event):
        self.update()
        super().enterEvent(event)

    def leaveEvent(self, event):
        self.update()
        super().leaveEvent(event)

    def paintEvent(self, _event):
        t = theme.tokens()
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        hover = self.underMouse()
        if hover:
            p.setPen(Qt.NoPen)
            p.setBrush(QColor(t["hover"]))
            p.drawRoundedRect(QRectF(self.rect()), 6, 6)
        dot = t.get(f"dot_{self.status}", t["dot_neutral"])
        p.setPen(Qt.NoPen)
        p.setBrush(QColor(dot))
        p.drawEllipse(QPointF(15, self.height() / 2), 3.5, 3.5)
        p.setFont(self.font())
        fm = p.fontMetrics()
        right = self.width() - 10
        if self.detail:
            p.setPen(QColor(t["text_faint"]))
            dw = fm.horizontalAdvance(self.detail)
            p.drawText(QRectF(right - dw, 0, dw, self.height()), Qt.AlignVCenter | Qt.AlignRight, self.detail)
            right -= dw + 8
        p.setPen(QColor(t["text"] if hover else t["text_muted"]))
        p.drawText(QRectF(28, 0, max(right - 28, 0), self.height()), Qt.AlignVCenter | Qt.AlignLeft,
                   fm.elidedText(self.plain_text, Qt.ElideRight, max(int(right - 28), 0)))
        p.end()

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.clicked.emit()
        super().mouseReleaseEvent(event)


class Toast(QFrame):
    """Brief message that fades in at the bottom right of its parent window."""

    def __init__(self, parent):
        super().__init__(parent)
        self.setObjectName("Toast")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 10, 14, 10)
        layout.setSpacing(10)
        self.icon = QLabel()
        self.icon.setFixedSize(16, 16)
        self.label = QLabel()
        self.label.setWordWrap(True)
        self.label.setMaximumWidth(380)  # see show_message
        layout.addWidget(self.icon, 0, Qt.AlignTop)
        layout.addWidget(self.label, 1)
        self.effect = QGraphicsOpacityEffect(self)
        self.effect.setOpacity(1.0)
        self.setGraphicsEffect(self.effect)
        self.fade = QPropertyAnimation(self.effect, b"opacity", self)
        self.fade.setDuration(160)
        self.fade.setEasingCurve(QEasingCurve.OutCubic)
        self.hide()
        self._timer = QTimer(self, singleShot=True)
        self._timer.timeout.connect(self.hide)

    def text(self):
        return self.label.text()

    def reposition(self):
        parent = self.parentWidget()
        self.adjustSize()
        self.move(parent.width() - self.width() - 20, parent.height() - self.height() - 20)

    def show_message(self, text, ms=6000, icon_name="check"):
        self.label.setText(text)
        # word-wrapped labels guess a narrow width; use the text's own width up to the maximum
        self.label.setFixedWidth(min(self.label.fontMetrics().horizontalAdvance(text) + 6, 380))
        self.icon.setPixmap(icons.pixmap(icon_name, theme.tokens()["accent_text"], 16))
        self.reposition()
        self.raise_()
        if not self.isVisible():
            self.effect.setOpacity(0.0)
            self.show()
            self.fade.stop()
            self.fade.setStartValue(0.0)
            self.fade.setEndValue(1.0)
            self.fade.start()
        self._timer.start(ms)


class EmptyState(QWidget):
    """Centred icon, title, explanation and buttons for a view with nothing to show yet."""

    def __init__(self, icon_name, title, text="", buttons=(), parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.addStretch(2)
        column = QVBoxLayout()
        column.setSpacing(8)
        self.icon_name = icon_name
        self.tile = QLabel()
        self.tile.setFixedSize(44, 44)
        self.tile.setAlignment(Qt.AlignCenter)
        self.tile.setObjectName("EmptyIcon")
        column.addWidget(self.tile, 0, Qt.AlignHCenter)
        column.addSpacing(6)
        self.title = label(title, "title")
        self.title.setAlignment(Qt.AlignCenter)
        self.text = label(text, "body", "Muted", wrap=True)
        self.text.setAlignment(Qt.AlignCenter)
        self.text.setMaximumWidth(440)
        self.text.setTextFormat(Qt.RichText)
        column.addWidget(self.title)
        column.addWidget(self.text, 0, Qt.AlignHCenter)
        row = QHBoxLayout()
        row.addStretch(1)
        for b in buttons:
            row.addWidget(b)
        row.addStretch(1)
        column.addSpacing(8)
        column.addLayout(row)
        layout.addLayout(column)
        layout.addStretch(3)
        self.retheme()
        theme.signals.changed.connect(self.retheme)

    def retheme(self, *_):
        t = theme.tokens()
        self.tile.setPixmap(icons.pixmap(self.icon_name, t["text_muted"], 20))
        self.tile.setStyleSheet(f"background: {t['surface_alt']}; border: 1px solid {t['border']}; "
                                "border-radius: 10px;")


# ---- finding detail -----------------------------------------------------------------------------

def detail_css():
    """Default stylesheet for the rich-text detail panes."""
    t = theme.tokens()
    return (f"a {{ color: {t['accent_text']}; text-decoration: none; }} "
            f"h2 {{ font-size: 17px; font-weight: 600; margin: 0 0 6px 0; }} "
            f"h4 {{ font-size: 13px; font-weight: 600; margin: 18px 0 4px 0; }} "
            f"p {{ margin: 0 0 6px 0; }} "
            f"td {{ padding: 3px 0; vertical-align: top; }} "
            f"td.k {{ color: {t['text_muted']}; padding-right: 16px; white-space: nowrap; }} "
            f".muted {{ color: {t['text_muted']}; }} "
            f"pre {{ font-family: 'JetBrains Mono', 'Cascadia Mono', Consolas, monospace; font-size: 12px; "
            f"background-color: {t['surface_alt']}; }}")


def _pill(sev):
    return theme.severity_badge(sev)


class FindingDetail(QTextBrowser):
    """Rich-text detail view for a single finding row (a pandas Series): title, properties, explanation."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setOpenExternalLinks(True)
        self.setObjectName("Detail")
        self.shared_counts = None  # {plugin_id: devices with it}, set by the owning panel
        self.document().setDocumentMargin(16)
        self.clear_detail()

    def clear_detail(self):
        self.document().setDefaultStyleSheet(detail_css())
        self.setHtml("<p class='muted'>Select a finding to see its details.</p>")

    def show_finding(self, row):
        def field(name):
            return display(name, row.get(name))

        def esc(text):
            return html.escape(text or "").replace("\n", "<br>")

        t = theme.tokens()
        cves = [c for c in (row.get("cves") or "").split(", ") if c]
        cve_links = ", ".join(f'<a href="https://nvd.nist.gov/vuln/detail/{c}">{c}</a>' for c in cves) or "—"
        see_also = [u for u in (row.get("see_also") or "").replace("\n", ", ").split(", ") if u.startswith("http")]
        plugin_id = field("plugin_id")
        port = field("port")
        proto = field("protocol")
        facts = []
        headline = [_pill(str(row.get("severity")))]
        if row.get("risk") is not None and row.get("risk") == row.get("risk"):
            from tenable_net.risk import band, explain_finding

            score, why = explain_finding(dict(row))
            headline.append(theme.band_badge(band(score), f"Risk {score:.0f}"))
            facts.append(("Risk score", f"{score:.0f} · {band(score)}<br><span class='muted'>{esc(why)}</span>"))
        if row.get("change"):
            headline.append(theme.status_badge(row.get("change")))
        if self.shared_counts is not None and row.get("plugin_id") in self.shared_counts:
            n = int(self.shared_counts[row.get("plugin_id")])
            facts.append(("Also on", f"{n} device{'s' if n != 1 else ''} in total"))
        facts += [
            ("Device", f"{esc(field('hostname'))} <span class='muted'>{esc(field('ip'))}</span>"),
            ("OS", esc(field("os"))),
            ("Port", f"{port}/{proto}" if port else "—"),
            ("VPR / CVSSv3", f"{field('vpr') or '—'} / {field('cvss3') or '—'}"),
            ("Exploit available", f"<span style='color:{t['bad']}'>Yes</span>"
                                  if is_true(row.get("exploit_available")) else "No"),
            ("State", esc(field("state")).title()),
            ("First / last found", f"{field('first_found')} / {field('last_found')}"),
            ("CVEs", cve_links),
            ("Plugin", f'<a href="https://www.tenable.com/plugins/nessus/{plugin_id}">{plugin_id}</a>'
                       f" <span class='muted'>· {esc(field('plugin_family'))}</span>"),
        ]
        rows = "".join(f"<tr><td class='k'>{k}</td><td>{v}</td></tr>" for k, v in facts)
        parts = [
            f"<h2>{esc(field('plugin_name'))}</h2>",
            f"<p>{' &nbsp;&nbsp; '.join(headline)}</p>",
            f"<table cellspacing='0' style='margin-top:8px'>{rows}</table>",
        ]
        if row.get("synopsis"):
            parts.append(f"<h4>Synopsis</h4><p>{esc(row.get('synopsis'))}</p>")
        if row.get("solution"):
            parts.append(f"<h4>Solution</h4><p>{esc(row.get('solution'))}</p>")
        if see_also:
            links = "<br>".join(f'<a href="{html.escape(u)}">{html.escape(u)}</a>' for u in see_also)
            parts.append(f"<h4>See also</h4><p>{links}</p>")
        output = row.get("output")
        if isinstance(output, str) and output.strip():
            parts.append(f"<h4>Plugin output</h4><pre>{html.escape(output[:20000])}</pre>")
        self.document().setDefaultStyleSheet(detail_css())
        self.setHtml("".join(parts))


# ---- background work ---------------------------------------------------------------------------

class Worker(QObject):
    """Runs fn(worker) on a QThread. fn may call worker.log.emit / worker.progress.emit."""

    log = Signal(str)
    progress = Signal(str, int)
    done = Signal(object)
    error = Signal(str)

    def __init__(self, fn):
        super().__init__()
        self._fn = fn
        self.cancel_requested = False

    def run(self):
        try:
            self.done.emit(self._fn(self))
        except Exception as exc:  # surfaced to the UI, never crash the thread
            self.error.emit(f"{type(exc).__name__}: {exc}\n\n{traceback.format_exc(limit=3)}")


def start_worker(fn, parent, on_done=None, on_error=None, on_log=None, on_progress=None):
    """Start fn in a background thread. Returns the worker (keep a reference to it)."""
    thread = QThread(parent)
    worker = Worker(fn)
    worker.moveToThread(thread)
    thread.started.connect(worker.run)
    for signal, slot in ((worker.done, on_done), (worker.error, on_error),
                         (worker.log, on_log), (worker.progress, on_progress)):
        if slot:
            signal.connect(slot)
    worker.done.connect(thread.quit)
    worker.error.connect(thread.quit)
    thread.finished.connect(thread.deleteLater)
    worker.thread = thread
    thread.start()
    return worker


def frame_row(df, i):
    return df.iloc[i] if 0 <= i < len(df) else pd.Series(dtype=object)
