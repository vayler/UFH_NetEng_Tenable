"""Devices tab: searchable device list on the left, the selected device's findings on the right."""

import html

import numpy as np
import pandas as pd
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QLineEdit, QSplitter, QVBoxLayout, QWidget

from tenable_net import reports
from tenable_net.gui.findings import FindingsPanel
from tenable_net.gui.models import DataFrameModel, MaskFilterProxy, display
from tenable_net.gui.widgets import SEVERITY_COLORS, fit_columns, make_table
from tenable_net.normalize import vendor_of

DEVICE_COLUMNS = ["hostname", "ip", "vendor", "critical", "high", "medium", "low", "max_vpr"]
DEVICE_FINDING_COLUMNS = [
    "severity", "plugin_id", "plugin_name", "vpr", "cves", "exploit_available", "port", "state", "last_found",
]


def device_frame(findings, assets):
    """One row per device: severity rollup from findings, plus assets that have no findings."""
    devices = reports.by_device(findings) if not findings.empty else pd.DataFrame(
        columns=["hostname", "ip", "os"])
    for col in ("critical", "high", "medium", "low", "total"):
        if col not in devices:
            devices[col] = 0
    if assets is not None and not assets.empty:
        extra = assets[~assets["hostname"].isin(devices["hostname"])][["hostname", "ip", "os"]]
        devices = pd.concat([devices, extra], ignore_index=True)
        for col in ("critical", "high", "medium", "low", "total"):
            devices[col] = devices[col].fillna(0).astype(int)
    devices["vendor"] = devices["os"].map(vendor_of)
    return devices.reset_index(drop=True)


class DevicesTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.findings = pd.DataFrame()
        self.assets = pd.DataFrame()

        self.search = QLineEdit(placeholderText="Filter devices…", clearButtonEnabled=True)
        self.search.textChanged.connect(self._filter_devices)
        self.devices_model = DataFrameModel()
        self.devices_proxy = MaskFilterProxy(self)
        self.devices_proxy.setSourceModel(self.devices_model)
        self.devices_view = make_table(self.devices_proxy, stretch_column="hostname")
        self.devices_view.selectionModel().currentRowChanged.connect(self._on_device)
        self.device_count = QLabel()

        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.addWidget(self.search)
        left_layout.addWidget(self.devices_view, 1)
        left_layout.addWidget(self.device_count)

        self.header = QLabel()
        self.header.setTextFormat(Qt.RichText)
        self.header.setWordWrap(True)
        self.panel = FindingsPanel(DEVICE_FINDING_COLUMNS)
        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.addWidget(self.header)
        right_layout.addWidget(self.panel, 1)

        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 3)
        splitter.setSizes([600, 840])
        layout = QVBoxLayout(self)
        layout.addWidget(splitter)

    def set_data(self, findings, assets):
        self.findings = findings
        self.assets = assets
        devices = device_frame(findings, assets)
        self.devices_model.set_frame(devices, DEVICE_COLUMNS)
        self.devices_view.sortByColumn(self.devices_model.column_index("critical"), Qt.DescendingOrder)
        fit_columns(self.devices_view, max_width=200)
        self._filter_devices()

    def _filter_devices(self):
        frame = self.devices_model.frame
        text = self.search.text().strip().lower()
        if frame.empty:
            mask = np.zeros(0, dtype=bool)
        elif text:
            mask = np.zeros(len(frame), dtype=bool)
            for col in ("hostname", "ip", "vendor", "os"):
                mask |= frame[col].fillna("").astype(str).str.lower().str.contains(text, regex=False).to_numpy()
        else:
            mask = np.ones(len(frame), dtype=bool)
        self.devices_proxy.set_mask(mask)
        self.device_count.setText(f"{int(mask.sum()):,} of {len(frame):,} devices")
        if self.devices_proxy.rowCount() and not self.devices_view.currentIndex().isValid():
            self.devices_view.selectRow(0)

    def select_device(self, hostname):
        self.search.clear()
        frame = self.devices_model.frame
        for proxy_row in range(self.devices_proxy.rowCount()):
            if frame.iloc[self.devices_proxy.source_row(proxy_row)]["hostname"] == hostname:
                self.devices_view.selectRow(proxy_row)
                self.devices_view.scrollTo(self.devices_proxy.index(proxy_row, 0))
                return True
        return False

    def _on_device(self, current, _previous):
        if not current.isValid():
            return
        device = self.devices_model.frame.iloc[self.devices_proxy.mapToSource(current).row()]
        hostname = device["hostname"]
        rows = self.findings[self.findings["hostname"] == hostname] if not self.findings.empty else self.findings
        self.panel.set_frame(rows)
        self.header.setText(self._header_html(device, len(rows)))

    def _header_html(self, device, n_findings):
        badges = " ".join(
            f'<span style="background:{SEVERITY_COLORS[s]}; color:{"#212121" if s == "medium" else "#fff"};">'
            f"&nbsp;{int(device.get(s) or 0)} {s}&nbsp;</span>"
            for s in ("critical", "high", "medium", "low")
        )
        extra = ""
        if not self.assets.empty:
            match = self.assets[self.assets["hostname"] == device["hostname"]]
            if not match.empty:
                a = match.iloc[0]
                bits = []
                if a.get("system_type"):
                    bits.append(f"Type: {html.escape(str(a['system_type']))}")
                if display("last_seen", a.get("last_seen")):
                    bits.append(f"Last seen: {display('last_seen', a.get('last_seen'))}")
                if a.get("tags"):
                    bits.append(f"Tags: {html.escape(str(a['tags']))}")
                extra = "<br><span style='color:gray'>" + " · ".join(bits) + "</span>" if bits else ""
        return (
            f"<h2 style='margin:0'>{html.escape(str(device['hostname']))}</h2>"
            f"<span style='color:gray'>{html.escape(str(device.get('ip') or ''))} · "
            f"{html.escape(str(device.get('os') or 'Unknown OS'))}</span>{extra}"
            f"<p>{badges} &nbsp; <b>{n_findings}</b> findings</p>"
        )
