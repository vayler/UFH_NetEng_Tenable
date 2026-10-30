"""Shared widgets: severity styling, KPI cards, finding detail pane, tables, background worker."""

import html
import traceback

import pandas as pd
from PySide6.QtCore import QObject, QPointF, QRectF, QSize, Qt, QThread, QTimer, Signal
from PySide6.QtGui import QColor, QIcon, QPainter, QPainterPath, QPen, QPixmap
from PySide6.QtWidgets import (
    QAbstractItemView, QFrame, QHBoxLayout, QHeaderView, QLabel, QStyledItemDelegate, QTableView, QTextBrowser,
    QVBoxLayout, QWidget,
)

from tenable_net import glossary
from tenable_net.gui import theme
from tenable_net.gui.models import RAW_ROLE, display, is_true
from tenable_net.gui.theme import SEVERITY_COLORS, SEVERITY_TEXT, severity_color  # noqa: F401 (re-exported)


def dot_icon(hex_color, size=10):
    """Small filled circle, e.g. a severity marker next to a checkbox label."""
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    p.setBrush(QColor(hex_color))
    p.setPen(Qt.NoPen)
    p.drawEllipse(0, 0, size - 1, size - 1)
    p.end()
    return QIcon(pm)


class SeverityDelegate(QStyledItemDelegate):
    """Paints the severity column as a soft tinted pill with dark ink (readable, not shouty)."""

    def paint(self, painter, option, index):
        sev = str(index.data(RAW_ROLE) or "")
        if sev not in SEVERITY_COLORS:
            return super().paint(painter, option, index)
        self.initStyleOption(option, index)
        style = option.widget.style() if option.widget else None
        option.text = ""
        if style:  # draws selection/hover background
            style.drawControl(style.ControlElement.CE_ItemViewItem, option, painter, option.widget)
        painter.save()
        painter.setRenderHint(QPainter.Antialiasing)
        rect = QRectF(option.rect).adjusted(6, 6, -6, -6)
        rect.setWidth(min(rect.width(), 70))
        path = QPainterPath()
        path.addRoundedRect(rect, 5, 5)
        painter.fillPath(path, QColor(theme.severity_tint(sev)))
        painter.setPen(QColor(theme.severity_ink(sev)))
        f = painter.font()
        f.setWeight(f.Weight.DemiBold)
        f.setPointSizeF(f.pointSizeF() * 0.92)
        painter.setFont(f)
        painter.drawText(rect, Qt.AlignCenter, sev.title())
        painter.restore()

    def sizeHint(self, option, index):
        return QSize(82, super().sizeHint(option, index).height())


class RiskDelegate(QStyledItemDelegate):
    """Risk score as a slim bar (band colour) with the number beside it."""

    def paint(self, painter, option, index):
        value = index.data(RAW_ROLE)
        try:
            score = float(value)
        except (TypeError, ValueError):
            return super().paint(painter, option, index)
        if score != score:  # NaN
            return super().paint(painter, option, index)
        from tenable_net.risk import band

        self.initStyleOption(option, index)
        style = option.widget.style() if option.widget else None
        option.text = ""
        if style:
            style.drawControl(style.ControlElement.CE_ItemViewItem, option, painter, option.widget)
        painter.save()
        painter.setRenderHint(QPainter.Antialiasing)
        r = QRectF(option.rect).adjusted(8, 0, -8, 0)
        text_w = 34
        track = QRectF(r.left(), r.center().y() - 3, max(r.width() - text_w - 6, 10), 6)
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(theme.tokens()["border"]))
        painter.drawRoundedRect(track, 3, 3)
        fill = QRectF(track)
        fill.setWidth(track.width() * max(0.0, min(score, 100.0)) / 100.0)
        painter.setBrush(QColor(theme.band_color(band(score))))
        painter.drawRoundedRect(fill, 3, 3)
        painter.setPen(option.palette.color(option.palette.ColorRole.Text))
        painter.drawText(QRectF(track.right() + 6, r.top(), text_w, r.height()), Qt.AlignVCenter | Qt.AlignRight,
                         f"{score:.0f}")
        painter.restore()

    def sizeHint(self, option, index):
        return QSize(120, super().sizeHint(option, index).height())


def make_table(model, stretch_column=None):
    """A sortable, read-only, row-selecting table view with sensible defaults."""
    view = QTableView()
    view.setModel(model)
    view.setSortingEnabled(True)
    view.setSelectionBehavior(QAbstractItemView.SelectRows)
    view.setSelectionMode(QAbstractItemView.SingleSelection)
    view.setEditTriggers(QAbstractItemView.NoEditTriggers)
    view.setAlternatingRowColors(True)
    view.setShowGrid(False)
    view.setWordWrap(False)
    view.setFrameShape(QFrame.NoFrame)
    view.verticalHeader().setVisible(False)
    view.verticalHeader().setDefaultSectionSize(theme.row_height())
    view.horizontalHeader().setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
    view.horizontalHeader().setResizeContentsPrecision(150)  # size columns from a sample, not every row
    view.horizontalHeader().setHighlightSections(False)
    view.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
    view.horizontalHeader().setStretchLastSection(stretch_column is None)
    view.setItemDelegate(QStyledItemDelegate(view))
    view._severity_delegate = SeverityDelegate(view)
    view._risk_delegate = RiskDelegate(view)
    view._stretch_column = stretch_column
    return view


def fit_columns(view, max_width=360, caps=None):
    """Size columns to content (sampled), apply the severity delegate and stretch column.

    caps: optional {column: max width} overriding max_width for specific columns."""
    caps = caps or {}
    source = view.model()
    while hasattr(source, "sourceModel"):
        source = source.sourceModel()
    columns = getattr(source, "columns", [])
    header = view.horizontalHeader()
    header.setSectionResizeMode(QHeaderView.Interactive)  # clear a stretch left from a previous column set
    for i, col in enumerate(columns):
        if col == "severity":
            view.setItemDelegateForColumn(i, view._severity_delegate)
        elif col == "risk":
            view.setItemDelegateForColumn(i, view._risk_delegate)
        view.resizeColumnToContents(i)
        if col == "severity":
            view.setColumnWidth(i, 88)
        elif col == "risk":
            view.setColumnWidth(i, 120)
        elif view.columnWidth(i) > caps.get(col, max_width):
            view.setColumnWidth(i, caps.get(col, max_width))
        if col == view._stretch_column:
            header.setSectionResizeMode(i, QHeaderView.Stretch)


class Sparkline(QWidget):
    """Tiny line chart of recent values (e.g. criticals per pull)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.values = []
        self.color = theme.color("brand")
        self.setMinimumHeight(22)

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
        w, h = self.width() - 4, self.height() - 4
        step = w / (len(self.values) - 1)
        points = [QPointF(2 + i * step, 2 + h - (v - lo) / span * h) for i, v in enumerate(self.values)]
        path = QPainterPath(points[0])
        for pt in points[1:]:
            path.lineTo(pt)
        p.setPen(QPen(self.color, 2))
        p.drawPath(path)
        p.setBrush(self.color)
        p.drawEllipse(points[-1], 2.5, 2.5)
        p.end()


class KpiCard(QFrame):
    """Headline number: caption (with an optional colour dot), value, change vs. the previous pull and an
    optional sparkline. All cards share one style; colour only appears in the small dot. Clickable."""

    clicked = Signal()

    def __init__(self, caption, accent=None, term=None, higher_is_bad=True, parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        self.accent = accent
        self.higher_is_bad = higher_is_bad
        self.setCursor(Qt.PointingHandCursor)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(4)
        self.caption = QLabel()
        self.caption.setObjectName("CardCaption")
        theme.set_font(self.caption, "caption", bold=True)
        self._caption_text = caption
        self.value = QLabel("–")
        theme.set_font(self.value, "kpi", bold=True)
        self.delta = QLabel()
        self.delta.setObjectName("Muted")
        theme.set_font(self.delta, "caption")
        self.spark = Sparkline()
        self.spark.setVisible(False)
        layout.addWidget(self.caption)
        layout.addWidget(self.value)
        layout.addWidget(self.delta)
        layout.addWidget(self.spark)
        self._render_caption()
        tip = glossary.TERMS.get(term) if term else None
        if tip:
            self.setToolTip(f"<b>{term}</b><br>{tip}")

    def _render_caption(self):
        dot = (f"<span style='color:{self.accent}'>●</span>&nbsp;" if self.accent else "")
        self.caption.setText(f"{dot}{html.escape(self._caption_text)}")

    def set_value(self, value):
        self.value.setText(value if isinstance(value, str) else f"{value:,}")

    def set_delta(self, change, suffix="since last pull"):
        """change: number vs. the previous pull (None hides it). Red when it moved the bad way."""
        if change is None:
            self.delta.setText("")
            return
        if change == 0:
            self.delta.setText(f"No change {suffix}")
            self.delta.setStyleSheet("")
            return
        worse = (change > 0) == self.higher_is_bad
        arrow = "▲" if change > 0 else "▼"
        color = theme.tokens()["bad" if worse else "good"]
        self.delta.setText(f"<span style='color:{color}; font-weight:600'>{arrow} {abs(change):,}</span> {suffix}")

    def set_trend(self, values):
        self.spark.set_values(values, self.accent or theme.tokens()["brand"])

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.clicked.emit()
        super().mouseReleaseEvent(event)


class Chip(QLabel):
    """Quiet status indicator: a coloured dot and a label inside a thin outline. Emits clicked."""

    clicked = Signal()

    def __init__(self, text="", status="neutral", parent=None):
        super().__init__(text, parent)
        self.setObjectName("Chip")
        self.setTextFormat(Qt.RichText)
        self.status = status
        self.set(text, status)

    def set(self, text, status="neutral", tooltip=None):
        self.status = status
        t = theme.tokens()
        # brighter dots: these sit on the dark sidebar
        dot = {"good": "#5FCF7A", "warn": "#FFB547", "bad": "#FF6B6B"}.get(status, "#8F9EBF")
        self.setText(f"<span style='color:{dot}'>●</span>&nbsp;{html.escape(text)}")
        self.plain_text = text
        if tooltip:
            self.setToolTip(tooltip)

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.clicked.emit()
        super().mouseReleaseEvent(event)


class Toast(QLabel):
    """Brief message in the corner of its parent window."""

    def __init__(self, parent):
        super().__init__(parent)
        self.setObjectName("Toast")
        self.setWordWrap(True)
        self.setMaximumWidth(420)
        self.hide()
        self._timer = QTimer(self, singleShot=True)
        self._timer.timeout.connect(self.hide)

    def show_message(self, text, ms=6000):
        self.setText(text)
        self.adjustSize()
        parent = self.parentWidget()
        self.move(parent.width() - self.width() - 24, 84)  # top right, under the top bar
        self.raise_()
        self.show()
        self._timer.start(ms)


def _pill(sev):
    return theme.severity_badge(sev)


class FindingDetail(QTextBrowser):
    """Rich-text detail view for a single finding row (a pandas Series)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setOpenExternalLinks(True)
        self.shared_counts = None  # {plugin_id: devices with it}, set by the owning panel
        self.clear_detail()

    def clear_detail(self):
        self.setHtml('<p style="color:gray">Select a finding to see details.</p>')

    def show_finding(self, row):
        def field(name):
            return display(name, row.get(name))

        def esc(text):
            return html.escape(text or "").replace("\n", "<br>")

        cves = [c for c in (row.get("cves") or "").split(", ") if c]
        cve_links = ", ".join(f'<a href="https://nvd.nist.gov/vuln/detail/{c}">{c}</a>' for c in cves) or "—"
        see_also = [u for u in (row.get("see_also") or "").replace("\n", ", ").split(", ") if u.startswith("http")]
        plugin_id = field("plugin_id")
        port = field("port")
        proto = field("protocol")
        facts = []
        if row.get("risk") is not None and row.get("risk") == row.get("risk"):
            from tenable_net.risk import band, explain_finding

            score, why = explain_finding(dict(row))
            facts.append(("Risk score", f"{theme.band_badge(band(score), f'{score:.0f} · {band(score)}')}"
                                        f"&nbsp; <span style='color:gray'>{esc(why)}</span>"))
        if self.shared_counts is not None and row.get("plugin_id") in self.shared_counts:
            n = int(self.shared_counts[row.get("plugin_id")])
            facts.append(("Also on", f"{n} device{'s' if n != 1 else ''} in total"))
        facts += [
            ("Device", f"{esc(field('hostname'))} ({esc(field('ip'))})"),
            ("OS", esc(field("os"))),
            ("Port", f"{port}/{proto}" if port else "—"),
            ("VPR / CVSSv3", f"{field('vpr') or '—'} / {field('cvss3') or '—'}"),
            ("Exploit available", "Yes" if is_true(row.get("exploit_available")) else "No"),
            ("State", esc(field("state"))),
            ("First / last found", f"{field('first_found')} / {field('last_found')}"),
            ("CVEs", cve_links),
            ("Plugin", f'<a href="https://www.tenable.com/plugins/nessus/{plugin_id}">{plugin_id}</a>'
                       f" · {esc(field('plugin_family'))}"),
        ]
        rows = "".join(
            f'<tr><td style="color:gray; padding-right:12px;">{k}</td><td>{v}</td></tr>' for k, v in facts
        )
        parts = [
            f"<h3>{esc(field('plugin_name'))}</h3>",
            f"<p>{_pill(str(row.get('severity')))}</p>",
            f"<table>{rows}</table>",
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
        self.setHtml("".join(parts))


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
