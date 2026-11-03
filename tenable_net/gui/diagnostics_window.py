"""Enrichment diagnostics: where each device falls out of the AKiPS -> Cisco pipeline."""

import html
import re

import numpy as np
import pandas as pd
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFileDialog, QFrame, QHBoxLayout, QLabel, QMessageBox, QPlainTextEdit, QStackedWidget, QTabBar, QTabWidget,
    QTextBrowser, QVBoxLayout, QWidget,
)

from tenable_net import akips, cisco, diagnostics, inventory
from tenable_net.gui import icons, theme
from tenable_net.gui.models import DataFrameModel, MaskFilterProxy
from tenable_net.gui.widgets import (
    SearchField, Splitter, button, detail_css, divider, fit_columns, label, make_table, start_worker,
)

DEVICE_COLUMNS = ["hostname", "stage", "reason", "vendor", "models", "with_serial", "akips_device"]
DETAIL_FIELDS = [
    ("in_tenable", "In Tenable"), ("ip", "IP"), ("akips_device", "AKiPS device"), ("match_method", "Matched by"),
    ("sys_descr", "sysDescr"), ("akips_classes", "AKiPS entity classes"), ("chassis_rule", "Chassis found by"),
    ("akips_issue", "AKiPS note"), ("members", "Chassis / stack members"), ("with_model", "…with model"),
    ("with_serial", "…with serial"), ("models", "Models"), ("serials", "Serials"), ("source", "Data source"),
    ("vendor", "Vendor"), ("vendor_source", "Vendor from"), ("contract", "Contract"),
    ("sw_status", "Software"), ("member_detail", "Per member"),
]


class FunnelStrip(QFrame):
    """Tenable devices → with inventory → with a model → with a serial → Cisco → fully enriched, then the
    AKiPS devices that matched nothing. The step widgets are built once; reloads only update their text."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("Panel")
        self.row = QHBoxLayout(self)
        self.row.setContentsMargins(18, 12, 18, 12)
        self.row.setSpacing(14)
        self.keys, self.values, self.captions, self.arrows = [], [], [], []

    def set_steps(self, funnel):
        steps = list(funnel.items())
        if [name for name, _value in steps] != self.keys:
            self._build([name for name, _value in steps])
        for (name, value), value_label in zip(steps, self.values):
            value_label.setText(f"{value:,}")
        muted = theme.tokens()["text_faint"]
        for arrow in self.arrows:
            arrow.setPixmap(icons.pixmap("chevron-right", muted, 14))

    def _build(self, keys):
        while self.row.count():  # only when the steps themselves change (normally just the first time)
            item = self.row.takeAt(0)
            for widget in ([item.widget()] if item.widget() else
                           [item.layout().itemAt(i).widget() for i in range(item.layout().count())]
                           if item.layout() else []):
                if widget is not None:
                    widget.hide()
                    widget.deleteLater()
        self.keys, self.values, self.captions, self.arrows = list(keys), [], [], []
        for i, name in enumerate(keys):
            if i == len(keys) - 1:
                self.row.addWidget(divider(vertical=True))
            elif i:
                arrow = QLabel()
                self.arrows.append(arrow)
                self.row.addWidget(arrow)
            block = QVBoxLayout()
            block.setSpacing(0)
            value = label("", "headline", weight="medium")
            caption = label(name[:1].upper() + name[1:], "caption", "Muted", wrap=True)
            block.addWidget(value)
            block.addWidget(caption)
            self.values.append(value)
            self.captions.append(caption)
            self.row.addLayout(block, 1)


class DiagnosticsWindow(QWidget):
    """Embedded in the main window (or a separate window); reload() recomputes the report from the cache."""

    def __init__(self, cache_dir, parent=None, embedded=False):
        super().__init__(parent, Qt.Widget if embedded else Qt.Window)
        self.setWindowTitle("Enrichment diagnostics")
        if not embedded:
            self.resize(1300, 820)
        self.cache_dir = cache_dir
        self.devices = pd.DataFrame()
        self.worker = None

        self.funnel = FunnelStrip()
        self.last_run = label("", "caption", "Muted", wrap=True)

        self.stage_model = DataFrameModel()
        self.stage_view = make_table(self.stage_model, stretch_column="stage")
        self.stage_view.setSortingEnabled(False)
        self.stage_view.setToolTip("Click a stage to list its devices")
        self.stage_view.selectionModel().currentRowChanged.connect(self._filter)
        self.search = SearchField("Filter devices…")
        self.search.textChanged.connect(self._filter)
        self.hint = label("", "body", wrap=True)
        self.hint.setTextFormat(Qt.RichText)
        self.hint.setContentsMargins(16, 10, 16, 12)

        self.device_model = DataFrameModel()
        self.device_proxy = MaskFilterProxy(self)
        self.device_proxy.setSourceModel(self.device_model)
        self.device_view = make_table(self.device_proxy)
        self.device_view.selectionModel().currentRowChanged.connect(self._on_device)
        self.count = label("", "caption", "Muted")

        self.detail = QTextBrowser()
        self.detail.document().setDocumentMargin(14)
        self.raw = QPlainTextEdit(readOnly=True)
        self.raw.setObjectName("Log")
        self.raw.setFont(theme.mono_font())
        self.raw.setPlaceholderText("'Show raw AKiPS data' lists everything AKiPS holds for the selected device.")
        detail_tabs = QTabWidget()
        detail_tabs.setDocumentMode(True)
        detail_tabs.addTab(self.detail, "Details")
        detail_tabs.addTab(self.raw, "Raw AKiPS data")
        self.detail_tabs = detail_tabs

        self.raw_button = button("Show raw AKiPS data", "ghost", "database")
        self.raw_button.clicked.connect(self.show_raw)
        self.requery_button = button("Re-query Cisco for this device", "ghost", "reload")
        self.requery_button.clicked.connect(self.requery)
        refresh = button("Refresh", "ghost", "reload")
        refresh.clicked.connect(self.reload)
        export_csv = button("Export CSV…", "ghost", "file")
        export_csv.clicked.connect(self.export_csv)
        bundle = button("Shareable report…", "ghost", "export",
                        "Zip of the diagnostics with hostnames, IPs and serials replaced by tokens")
        bundle.clicked.connect(self.export_bundle)
        self.status = label("", "caption", "Muted")

        self.unmatched_model = DataFrameModel()
        self.unmatched_view = make_table(self.unmatched_model, stretch_column="sys_descr")

        # layout: stages | devices + detail
        left = QWidget()
        lv = QVBoxLayout(left)
        lv.setContentsMargins(0, 0, 0, 0)
        lv.setSpacing(0)
        head = QHBoxLayout()
        head.setContentsMargins(16, 12, 16, 8)
        head.addWidget(label("Where devices stop", "section"))
        head.addStretch(1)
        lv.addLayout(head)
        lv.addWidget(self.stage_view, 1)
        lv.addWidget(divider())
        lv.addWidget(self.hint)

        right = QWidget()
        rv = QVBoxLayout(right)
        rv.setContentsMargins(0, 0, 0, 0)
        rv.setSpacing(0)
        bar = QHBoxLayout()
        bar.setContentsMargins(12, 8, 12, 8)
        bar.setSpacing(6)
        bar.addWidget(self.search, 1)
        bar.addWidget(self.count)
        rv.addLayout(bar)
        rv.addWidget(divider())
        lower = QWidget()
        low = QVBoxLayout(lower)
        low.setContentsMargins(0, 0, 0, 0)
        low.setSpacing(0)
        buttons = QHBoxLayout()
        buttons.setContentsMargins(10, 6, 10, 0)
        for b in (self.raw_button, self.requery_button):
            buttons.addWidget(b)
        buttons.addStretch(1)
        low.addLayout(buttons)
        low.addWidget(detail_tabs, 1)
        inner = Splitter(Qt.Vertical, line=True)
        inner.addWidget(self.device_view)
        inner.addWidget(lower)
        inner.setSizes([380, 300])
        rv.addWidget(inner, 1)

        split = Splitter(Qt.Horizontal, line=True)
        split.addWidget(left)
        split.addWidget(right)
        split.setSizes([360, 840])

        unmatched_page = QWidget()
        uv = QVBoxLayout(unmatched_page)
        uv.setContentsMargins(0, 0, 0, 0)
        uv.setSpacing(0)
        note = label("AKiPS devices that didn't match any Tenable device by IP, sysName or name. If one of them is a "
                     "Tenable device under another name, add <code>akips_device,tenable_hostname</code> to "
                     f"<code>{html.escape(str(inventory.aliases_path()))}</code> and click Refresh.", "body", "Muted",
                     wrap=True)
        note.setTextFormat(Qt.RichText)
        note.setContentsMargins(16, 12, 16, 12)
        uv.addWidget(note)
        uv.addWidget(divider())
        uv.addWidget(self.unmatched_view, 1)

        self.tabs = QTabBar()
        self.tabs.setDrawBase(False)
        self.tabs.setExpanding(False)
        self.tabs.addTab("Devices")
        self.tabs.addTab("Unmatched AKiPS devices")
        self.pages = QStackedWidget()
        self.pages.addWidget(split)
        self.pages.addWidget(unmatched_page)
        self.tabs.currentChanged.connect(self.pages.setCurrentIndex)
        toolbar = QHBoxLayout()
        toolbar.setContentsMargins(14, 6, 10, 0)
        toolbar.setSpacing(4)
        toolbar.addWidget(self.tabs, 0, Qt.AlignBottom)
        toolbar.addStretch(1)
        toolbar.addWidget(self.status)
        for b in (refresh, export_csv, bundle):
            toolbar.addWidget(b)

        top = QVBoxLayout()
        top.setContentsMargins(18, 14, 18, 4)
        top.setSpacing(8)
        top.addWidget(self.funnel)
        top.addWidget(self.last_run)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addLayout(top)
        layout.addLayout(toolbar)
        layout.addWidget(divider())
        layout.addWidget(self.pages, 1)
        self.reload()

    # ---- data ----------------------------------------------------------------
    def reload(self):
        funnel, self.devices, unmatched = diagnostics.enrichment_report(self.cache_dir)
        self.funnel.set_steps(funnel)
        run = diagnostics.last_run(self.cache_dir)
        if run:
            parts = [f"{k}: {v.get('found', 0)}/{v.get('sent', 0)} found"
                     + (f", {v['rejected']} rejected" if v.get("rejected") else "")
                     + (f", FAILED: {v['failed']}" if v.get("failed") else "")
                     for k, v in (run.get("sections") or {}).items()]
            self.last_run.setText(f"Last Cisco run {run.get('at')} · APIs: {', '.join(run.get('apis') or []) or 'none'}"
                                  f" · {'; '.join(parts) or 'nothing sent'}")
        else:
            self.last_run.setText("No Cisco lookups recorded yet.")
        stages = diagnostics.stage_counts(self.devices)
        all_row = pd.DataFrame([{"stage": "All devices", "devices": len(self.devices), "hint": ""}])
        self.stage_model.set_frame(pd.concat([all_row, stages], ignore_index=True), ["stage", "devices"])
        fit_columns(self.stage_view)
        cols = [c for c in DEVICE_COLUMNS if c in self.devices]
        self.device_model.set_frame(self.devices, cols)
        fit_columns(self.device_view, max_width=200, caps={"reason": 340, "models": 140, "akips_device": 140,
                                                           "stage": 190})
        self.unmatched_model.set_frame(unmatched)
        fit_columns(self.unmatched_view, max_width=260)
        self.tabs.setTabText(1, f"Unmatched AKiPS devices ({len(unmatched)})")
        self.stage_view.selectRow(1 if len(stages) else 0)  # first problem stage
        self._filter()

    def select_stage(self, stage):
        frame = self.stage_model.frame
        matches = frame.index[frame["stage"] == stage].tolist()
        if matches:
            self.stage_view.selectRow(matches[0])

    def current_stage(self):
        idx = self.stage_view.currentIndex()
        if not idx.isValid() or idx.row() == 0:
            return None
        return self.stage_model.frame.iloc[idx.row()]["stage"]

    def _filter(self, *_):
        frame = self.device_model.frame
        if frame.empty:
            self.device_proxy.set_mask(np.zeros(0, dtype=bool))
            self.count.setText("No devices")
            return
        mask = np.ones(len(frame), dtype=bool)
        stage = self.current_stage()
        if stage:
            mask &= (frame["stage"] == stage).to_numpy()
            self.hint.setText(f"<b>What to do</b><br><span style='color:{theme.tokens()['text_muted']}'>"
                              f"{html.escape(diagnostics.HINTS.get(stage, ''))}</span>")
        else:
            self.hint.setText("")
        self.hint.setVisible(bool(stage))
        text = self.search.text().strip().lower()
        if text:
            hay = frame[[c for c in ("hostname", "reason", "models", "serials", "akips_device", "ip") if c in frame]]
            mask &= hay.fillna("").astype(str).apply(lambda col: col.str.lower().str.contains(text, regex=False)).any(axis=1).to_numpy()
        self.device_proxy.set_mask(mask)
        self.count.setText(f"{int(mask.sum()):,} of {len(frame):,} devices")
        if self.device_proxy.rowCount():
            self.device_view.selectRow(0)
        else:
            self.detail.clear()

    def selected(self):
        idx = self.device_view.currentIndex()
        if not idx.isValid():
            return None
        return self.device_model.frame.iloc[self.device_proxy.mapToSource(idx).row()]

    def _on_device(self, current, _previous):
        row = self.selected()
        if row is None:
            return
        stage = str(row["stage"])
        dot = theme.status_dot(stage) or theme.tokens()["dot_bad"]
        lines = [f"<h2>{html.escape(str(row['hostname']))}</h2>",
                 f"<p>{theme.dot_badge(dot, html.escape(stage))}"
                 f"{' <span class=muted>— ' + html.escape(str(row['reason'])) + '</span>' if row['reason'] else ''}"
                 "</p>"]
        if row.get("hint"):
            lines.append(f"<p class='muted'>{html.escape(row['hint'])}</p>")
        cells = []
        for key, field_label in DETAIL_FIELDS:
            value = row.get(key)
            if value is None or (isinstance(value, float) and pd.isna(value)) or value == "":
                continue
            text = html.escape(str(value)).replace("; ", "<br>") if key == "member_detail" else html.escape(str(value))
            cells.append(f"<tr><td class='k'>{field_label}</td><td>{text}</td></tr>")
        lines.append(f"<table cellspacing='0' style='margin-top:6px'>{''.join(cells)}</table>")
        self.detail.document().setDefaultStyleSheet(detail_css())
        self.detail.setHtml("".join(lines))
        self.raw_button.setEnabled(bool(row.get("akips_device")) and akips.configured())
        self.requery_button.setEnabled(row.get("vendor") == "Cisco" and cisco.configured())

    # ---- actions ---------------------------------------------------------------
    def show_raw(self):
        row = self.selected()
        if row is None or not row.get("akips_device"):
            return
        device = str(row["akips_device"]).split(", ")[0]
        self.raw.setPlainText(f"Asking AKiPS for everything it holds on {device} …")
        self.detail_tabs.setCurrentWidget(self.raw)
        self.raw_button.setEnabled(False)
        self.worker = start_worker(lambda _w: akips.get_client().device_dump(device), self,
                                   on_done=self._raw_done, on_error=self._raw_failed)

    def _raw_done(self, text):
        self.raw_button.setEnabled(True)
        lines = text.splitlines()
        interesting = [ln for ln in lines if re.search(r"serial|entPhysical|sysDescr|sysName|ip4addr", ln, re.I)]
        self.raw.setPlainText(
            f"{len(lines)} attributes; {len(interesting)} look relevant (serial / entPhysical / sys*):\n\n"
            + "\n".join(interesting) + "\n\n---- everything ----\n" + text)

    def _raw_failed(self, message):
        self.raw_button.setEnabled(True)
        self.raw.setPlainText(f"AKiPS query failed:\n{message}")

    def requery(self):
        row = self.selected()
        if row is None:
            return
        host = row["hostname"]
        self.requery_button.setEnabled(False)
        self.status.setText(f"Re-querying Cisco for {host} …")
        self._log = []

        def job(worker):
            inventory.refresh_cisco_device(self.cache_dir, cisco.get_client(), host, log=worker.log.emit)
            return host

        self.worker = start_worker(job, self, on_done=self._requery_done, on_error=self._requery_failed,
                                   on_log=self._collect_log)

    def _collect_log(self, message):
        self._log.append(re.sub(r"\[/?[a-z ]+\]", "", str(message)))

    def _requery_done(self, host):
        self.requery_button.setEnabled(True)
        self.status.setText(" · ".join(line.strip() for line in self._log[-4:]))
        self.reload()
        self._select(host)

    def _requery_failed(self, message):
        self.requery_button.setEnabled(True)
        self.status.setText(f"Cisco re-query failed: {message.splitlines()[0]}")
        self.reload()

    def _select(self, host):
        self.stage_view.selectRow(0)
        frame = self.device_model.frame
        for r in range(self.device_proxy.rowCount()):
            if frame.iloc[self.device_proxy.source_row(r)]["hostname"] == host:
                self.device_view.selectRow(r)
                return

    def export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export diagnostics", "enrichment_diagnostics.csv", "CSV (*.csv)")
        if path:
            self.devices.to_csv(path, index=False)
            self.status.setText(f"Saved {path}")

    def export_bundle(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export shareable report", "enrichment_report.zip", "Zip (*.zip)")
        if path:
            diagnostics.export_bundle(self.cache_dir, path, scrub=True)
            QMessageBox.information(self, "Shareable report",
                                    f"Saved {path}\n\nHostnames, IPs and serial numbers are replaced with tokens. "
                                    "Have a quick look before sharing it.")

    def refresh_theme(self):
        self.reload()
