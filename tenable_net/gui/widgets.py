"""Shared widgets: severity styling, KPI cards, finding detail pane, tables, background worker."""

import html
import traceback

import pandas as pd
from PySide6.QtCore import QObject, QRectF, QSize, Qt, QThread, Signal
from PySide6.QtGui import QColor, QPainter, QPainterPath
from PySide6.QtWidgets import (
    QAbstractItemView, QFrame, QHeaderView, QLabel, QStyledItemDelegate, QTableView, QTextBrowser,
    QVBoxLayout,
)

from tenable_net.gui.models import RAW_ROLE, display, is_true

SEVERITY_COLORS = {
    "critical": "#c62828",
    "high": "#ef6c00",
    "medium": "#f9a825",
    "low": "#1e88e5",
    "info": "#78909c",
}
SEVERITY_TEXT = {"medium": "#212121"}


def severity_color(severity):
    return QColor(SEVERITY_COLORS.get(str(severity), "#9e9e9e"))


class SeverityDelegate(QStyledItemDelegate):
    """Paints the severity column as a colored pill."""

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
        rect = QRectF(option.rect).adjusted(4, 4, -4, -4)
        rect.setWidth(min(rect.width(), 72))
        path = QPainterPath()
        path.addRoundedRect(rect, rect.height() / 2, rect.height() / 2)
        painter.fillPath(path, severity_color(sev))
        painter.setPen(QColor(SEVERITY_TEXT.get(sev, "#ffffff")))
        font = painter.font()
        font.setBold(True)
        font.setPointSizeF(font.pointSizeF() * 0.85)
        painter.setFont(font)
        painter.drawText(rect, Qt.AlignCenter, sev.upper())
        painter.restore()

    def sizeHint(self, option, index):
        return QSize(84, super().sizeHint(option, index).height())


def make_table(model, stretch_column=None):
    """A sortable, read-only, row-selecting table view with sensible defaults."""
    view = QTableView()
    view.setModel(model)
    view.setSortingEnabled(True)
    view.setSelectionBehavior(QAbstractItemView.SelectRows)
    view.setSelectionMode(QAbstractItemView.SingleSelection)
    view.setEditTriggers(QAbstractItemView.NoEditTriggers)
    view.setAlternatingRowColors(True)
    view.setWordWrap(False)
    view.verticalHeader().setVisible(False)
    view.verticalHeader().setDefaultSectionSize(26)
    view.horizontalHeader().setHighlightSections(False)
    view.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
    view.horizontalHeader().setStretchLastSection(stretch_column is None)
    view.setItemDelegate(QStyledItemDelegate(view))
    view._severity_delegate = SeverityDelegate(view)
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
    for i, col in enumerate(columns):
        if col == "severity":
            view.setItemDelegateForColumn(i, view._severity_delegate)
        view.resizeColumnToContents(i)
        if col == "severity":
            view.setColumnWidth(i, 88)
        elif view.columnWidth(i) > caps.get(col, max_width):
            view.setColumnWidth(i, caps.get(col, max_width))
        if col == view._stretch_column:
            header.setSectionResizeMode(i, QHeaderView.Stretch)


class KpiCard(QFrame):
    def __init__(self, caption, accent="#546e7a", parent=None):
        super().__init__(parent)
        self.setObjectName("KpiCard")
        self.setStyleSheet(
            f"#KpiCard {{ border: 1px solid palette(mid); border-left: 5px solid {accent};"
            " border-radius: 6px; background: palette(base); }"
        )
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        self.value = QLabel("–")
        font = self.value.font()
        font.setPointSizeF(font.pointSizeF() * 2.0)
        font.setBold(True)
        self.value.setFont(font)
        self.caption = QLabel(caption)
        self.caption.setStyleSheet("color: palette(placeholder-text);")
        layout.addWidget(self.value)
        layout.addWidget(self.caption)

    def set_value(self, value):
        self.value.setText(value if isinstance(value, str) else f"{value:,}")


def _pill(sev):
    color = SEVERITY_COLORS.get(sev, "#9e9e9e")
    text = SEVERITY_TEXT.get(sev, "#ffffff")
    return (f'<span style="background:{color}; color:{text}; font-weight:bold;">'
            f'&nbsp;{html.escape(sev.upper())}&nbsp;</span>')


class FindingDetail(QTextBrowser):
    """Rich-text detail view for a single finding row (a pandas Series)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setOpenExternalLinks(True)
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
        facts = [
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
