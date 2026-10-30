"""Tools -> Enrichment diagnostics: where each device falls out of the AKiPS -> Cisco pipeline."""

import html
import re

import numpy as np
import pandas as pd
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFileDialog, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPlainTextEdit, QPushButton, QSplitter,
    QTabWidget, QTextBrowser, QVBoxLayout, QWidget,
)

from tenable_net import akips, cisco, diagnostics, inventory
from tenable_net.gui.models import DataFrameModel, MaskFilterProxy
from tenable_net.gui.widgets import fit_columns, make_table, start_worker

DEVICE_COLUMNS = ["hostname", "stage", "reason", "vendor", "models", "with_serial", "akips_device"]
STAGE_COLORS = {"OK": "#43a047", "Not Cisco": "#9e9e9e", "Not looked up yet": "#fb8c00"}
DETAIL_FIELDS = [
    ("in_tenable", "In Tenable"), ("ip", "IP"), ("akips_device", "AKiPS device"), ("match_method", "Matched by"),
    ("sys_descr", "sysDescr"), ("akips_classes", "AKiPS entity classes"), ("chassis_rule", "Chassis found by"),
    ("akips_issue", "AKiPS note"), ("members", "Chassis / stack members"), ("with_model", "…with model"),
    ("with_serial", "…with serial"), ("models", "Models"), ("serials", "Serials"), ("source", "Data source"),
    ("vendor", "Vendor"), ("vendor_source", "Vendor from"), ("contract", "Contract"),
    ("sw_status", "Software"), ("member_detail", "Per member"),
]


class DiagnosticsWindow(QWidget):
    """Non-modal window; reload() recomputes the report from the cache."""

    def __init__(self, cache_dir, parent=None):
        super().__init__(parent, Qt.Window)
        self.setWindowTitle("Enrichment diagnostics")
        self.resize(1300, 820)
        self.cache_dir = cache_dir
        self.devices = pd.DataFrame()
        self.worker = None

        self.funnel = QLabel()
        self.funnel.setTextFormat(Qt.RichText)
        self.funnel.setWordWrap(True)
        self.last_run = QLabel()
        self.last_run.setWordWrap(True)
        self.last_run.setStyleSheet("color: palette(placeholder-text);")

        self.stage_model = DataFrameModel()
        self.stage_view = make_table(self.stage_model, stretch_column="stage")
        self.stage_view.setSortingEnabled(False)
        self.stage_view.setToolTip("Click a stage to list its devices")
        self.stage_view.selectionModel().currentRowChanged.connect(self._filter)
        self.search = QLineEdit(placeholderText="Filter devices…", clearButtonEnabled=True)
        self.search.textChanged.connect(self._filter)
        self.hint = QLabel()
        self.hint.setWordWrap(True)

        self.device_model = DataFrameModel()
        self.device_proxy = MaskFilterProxy(self)
        self.device_proxy.setSourceModel(self.device_model)
        self.device_view = make_table(self.device_proxy, stretch_column="reason")
        self.device_view.selectionModel().currentRowChanged.connect(self._on_device)
        self.count = QLabel()

        self.detail = QTextBrowser()
        self.raw = QPlainTextEdit(readOnly=True)
        self.raw.setPlaceholderText("'Show raw AKiPS data' lists everything AKiPS holds for the selected device.")
        detail_tabs = QTabWidget()
        detail_tabs.addTab(self.detail, "Details")
        detail_tabs.addTab(self.raw, "Raw AKiPS data")
        self.detail_tabs = detail_tabs

        self.raw_button = QPushButton("Show raw AKiPS data")
        self.raw_button.clicked.connect(self.show_raw)
        self.requery_button = QPushButton("Re-query Cisco for this device")
        self.requery_button.clicked.connect(self.requery)
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self.reload)
        export_csv = QPushButton("Export CSV…")
        export_csv.clicked.connect(self.export_csv)
        bundle = QPushButton("Export shareable report…")
        bundle.setToolTip("Zip of the diagnostics with hostnames, IPs and serials replaced by tokens")
        bundle.clicked.connect(self.export_bundle)
        self.status = QLabel()

        self.unmatched_model = DataFrameModel()
        self.unmatched_view = make_table(self.unmatched_model, stretch_column="sys_descr")

        # layout
        left = QWidget()
        lv = QVBoxLayout(left)
        lv.setContentsMargins(0, 0, 0, 0)
        lv.addWidget(QLabel("<b>Where devices stop</b> (first failing stage)"))
        lv.addWidget(self.stage_view, 1)
        lv.addWidget(self.hint)

        right = QWidget()
        rv = QVBoxLayout(right)
        rv.setContentsMargins(0, 0, 0, 0)
        rv.addWidget(self.search)
        rv.addWidget(self.device_view, 3)
        rv.addWidget(self.count)
        buttons = QHBoxLayout()
        for b in (self.raw_button, self.requery_button):
            buttons.addWidget(b)
        buttons.addStretch(1)
        rv.addLayout(buttons)
        rv.addWidget(detail_tabs, 2)

        split = QSplitter(Qt.Horizontal)
        split.addWidget(left)
        split.addWidget(right)
        split.setSizes([380, 920])

        tabs = QTabWidget()
        tabs.addTab(split, "Devices")
        unmatched_page = QWidget()
        uv = QVBoxLayout(unmatched_page)
        uv.addWidget(QLabel("AKiPS devices that didn't match any Tenable device by IP, sysName or name. If one of "
                            "them is a Tenable device under another name, add <code>akips_device,tenable_hostname</code> "
                            f"to <code>{html.escape(str(inventory.aliases_path()))}</code> and click Refresh."))
        uv.addWidget(self.unmatched_view)
        tabs.addTab(unmatched_page, "Unmatched AKiPS devices")
        self.tabs = tabs

        bottom = QHBoxLayout()
        bottom.addWidget(self.status, 1)
        for b in (refresh, export_csv, bundle):
            bottom.addWidget(b)

        layout = QVBoxLayout(self)
        layout.addWidget(self.funnel)
        layout.addWidget(self.last_run)
        layout.addWidget(tabs, 1)
        layout.addLayout(bottom)
        self.reload()

    # ---- data ----------------------------------------------------------------
    def reload(self):
        funnel, self.devices, unmatched = diagnostics.enrichment_report(self.cache_dir)
        steps = list(funnel.items())
        self.funnel.setText(
            "<b>Funnel:</b> " + " &nbsp;→&nbsp; ".join(f"{html.escape(k)} <b>{v:,}</b>" for k, v in steps[:-1])
            + f" &nbsp;·&nbsp; {html.escape(steps[-1][0])}: <b>{steps[-1][1]:,}</b>")
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
        fit_columns(self.device_view, max_width=200, caps={"models": 140, "akips_device": 140, "stage": 170})
        self.unmatched_model.set_frame(unmatched)
        fit_columns(self.unmatched_view, max_width=260)
        self.tabs.setTabText(1, f"Unmatched AKiPS devices ({len(unmatched)})")
        self.stage_view.selectRow(1 if len(stages) else 0)  # first problem stage
        self._filter()

    def current_stage(self):
        idx = self.stage_view.currentIndex()
        if not idx.isValid() or idx.row() == 0:
            return None
        return self.stage_model.frame.iloc[idx.row()]["stage"]

    def _filter(self, *_):
        frame = self.device_model.frame
        if frame.empty:
            self.device_proxy.set_mask(np.zeros(0, dtype=bool))
            self.count.setText("No devices.")
            return
        mask = np.ones(len(frame), dtype=bool)
        stage = self.current_stage()
        if stage:
            mask &= (frame["stage"] == stage).to_numpy()
            self.hint.setText(f"<b>What to do:</b> {html.escape(diagnostics.HINTS.get(stage, ''))}")
        else:
            self.hint.setText("")
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
        color = STAGE_COLORS.get(row["stage"], "#e53935")
        lines = [f"<h3 style='margin:0'>{html.escape(str(row['hostname']))}</h3>",
                 f"<p><b style='color:{color}'>{html.escape(row['stage'])}</b>"
                 f"{' — ' + html.escape(str(row['reason'])) if row['reason'] else ''}</p>"]
        if row.get("hint"):
            lines.append(f"<p><i>{html.escape(row['hint'])}</i></p>")
        cells = []
        for key, label in DETAIL_FIELDS:
            value = row.get(key)
            if value is None or (isinstance(value, float) and pd.isna(value)) or value == "":
                continue
            text = html.escape(str(value)).replace("; ", "<br>") if key == "member_detail" else html.escape(str(value))
            cells.append(f"<tr><td style='color:gray; padding-right:12px; white-space:nowrap'>{label}</td><td>{text}</td></tr>")
        lines.append(f"<table>{''.join(cells)}</table>")
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

