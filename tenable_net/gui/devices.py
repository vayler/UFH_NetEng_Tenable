"""Devices tab: searchable device list on the left, the selected device's hardware + findings on the right."""

import html
from datetime import timedelta

import numpy as np
import pandas as pd
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QComboBox, QHBoxLayout, QLabel, QLineEdit, QSplitter, QVBoxLayout, QWidget

from tenable_net import reports, risk
from tenable_net.gui.findings import FindingsPanel
from tenable_net.gui import theme
from tenable_net.gui.models import DataFrameModel, MaskFilterProxy, display
from tenable_net.gui.widgets import SEVERITY_COLORS, SEVERITY_TEXT, fit_columns, make_table
from tenable_net.inventory import device_summary, has_lifecycle
from tenable_net.normalize import vendor_of

DEVICE_COLUMNS = ["hostname", "risk", "ip", "vendor", "critical", "high", "medium", "low"]
# Hardware mode has more columns, so only critical/high counts are listed (the header shows all four).
HARDWARE_DEVICE_COLUMNS = ["hostname", "risk", "model", "contract", "sw_status", "lifecycle", "critical", "high"]
DEVICE_FINDING_COLUMNS = [
    "risk", "severity", "plugin_id", "plugin_name", "vpr", "cves", "exploit_available", "port", "days_open",
    "last_found",
]
LIFECYCLE_FILTERS = {
    "All devices": None,
    "Past last day of support": lambda d: d["lifecycle"] == "Past LDoS",
    "LDoS within 12 months": lambda d: d["ldos"].notna() & (d["ldos"] >= pd.Timestamp.now().normalize())
    & (d["ldos"] <= pd.Timestamp.now().normalize() + timedelta(days=365)),
    "Not under contract": lambda d: d["contract"] == "Not covered",
    "Contract ends within 90 days": lambda d: d["contract_end"].notna()
    & (d["contract_end"] <= pd.Timestamp.now().normalize() + timedelta(days=90)),
    "Software upgrade suggested": lambda d: d["sw_status"] == "Upgrade suggested",
    "In AKiPS but not in Tenable": lambda d: d["in_tenable"] == False,  # noqa: E712
    "No hardware data": lambda d: d["model"].fillna("") == "",
}
SEVERITY_COLUMNS = ("critical", "high", "medium", "low", "total")


def device_frame(findings, assets, inventory=None):
    """One row per device: severity rollup from findings, assets without findings, and (when an
    inventory is loaded) hardware/lifecycle columns plus AKiPS devices Tenable doesn't know about."""
    devices = reports.by_device(findings) if not findings.empty else pd.DataFrame(columns=["hostname", "ip", "os"])
    if assets is not None and not assets.empty:
        extra = assets[~assets["hostname"].isin(devices["hostname"])][["hostname", "ip", "os"]]
        devices = pd.concat([devices, extra], ignore_index=True)
    devices["in_tenable"] = True

    if inventory is not None and not inventory.empty:
        hw = device_summary(inventory)
        ips = inventory.groupby("hostname")["ip"].first()
        vendors = inventory.groupby("hostname")["vendor"].first()
        missing = hw[~hw["hostname"].isin(devices["hostname"])]
        devices = pd.concat([devices, pd.DataFrame({
            "hostname": missing["hostname"], "ip": missing["hostname"].map(ips),
            "os": missing["hostname"].map(vendors), "in_tenable": missing["in_tenable"],
        })], ignore_index=True)
        devices = devices.merge(hw.drop(columns=["in_tenable"]), on="hostname", how="left")
    for col in SEVERITY_COLUMNS:
        devices[col] = devices[col].fillna(0).astype(int) if col in devices else 0
    for col in ("model", "lifecycle", "contract", "sw_status", "recommended_sw"):
        devices[col] = devices[col].fillna("") if col in devices else ""
    for col in ("ldos", "contract_end"):
        if col not in devices:
            devices[col] = pd.NaT
    devices["vendor"] = devices["os"].map(vendor_of)
    return devices.reset_index(drop=True)


class DevicesTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.findings = pd.DataFrame()
        self.assets = pd.DataFrame()
        self.inventory = pd.DataFrame()
        self.enrichment = {}

        self.search = QLineEdit(placeholderText="Filter devices (name, IP, model, serial)…", clearButtonEnabled=True)
        self.search.textChanged.connect(self._filter_devices)
        self.lifecycle_filter = QComboBox()
        self.lifecycle_filter.addItems(list(LIFECYCLE_FILTERS))
        self.lifecycle_filter.setToolTip("Hardware lifecycle / contract filter (needs inventory data)")
        self.lifecycle_filter.currentIndexChanged.connect(self._filter_devices)
        self.devices_model = DataFrameModel()
        self.devices_proxy = MaskFilterProxy(self)
        self.devices_proxy.setSourceModel(self.devices_model)
        self.devices_view = make_table(self.devices_proxy, stretch_column="hostname")
        self.devices_view.selectionModel().currentRowChanged.connect(self._on_device)
        self.device_count = QLabel()

        filters = QHBoxLayout()
        filters.addWidget(self.search, 3)
        filters.addWidget(self.lifecycle_filter, 2)
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.addLayout(filters)
        left_layout.addWidget(self.devices_view, 1)
        left_layout.addWidget(self.device_count)

        self.header = QLabel()
        self.header.setTextFormat(Qt.RichText)
        self.header.setWordWrap(True)
        self.header.setOpenExternalLinks(True)
        self.header.setTextInteractionFlags(Qt.TextBrowserInteraction)
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
        splitter.setSizes([700, 740])
        layout = QVBoxLayout(self)
        layout.addWidget(splitter)

    def set_data(self, findings, assets, inventory=None, enrichment=None):
        self.enrichment = enrichment or {}
        self.findings = findings
        self.plugin_devices = (findings.groupby("plugin_id")["hostname"].nunique().to_dict()
                               if not findings.empty else {})
        self.panel.fleet_counts = self.plugin_devices  # "also on N devices" counts the whole fleet
        self.assets = assets
        self.inventory = inventory if inventory is not None else pd.DataFrame()
        has_hw = not self.inventory.empty
        self.lifecycle_filter.setVisible(has_hw)
        if not has_hw:
            self.lifecycle_filter.setCurrentIndex(0)
        devices = device_frame(findings, assets, self.inventory if has_hw else None)
        hw_summary = device_summary(self.inventory) if has_hw else None
        self.hw_by_host = {r["hostname"]: r for r in hw_summary.to_dict("records")} if hw_summary is not None else {}
        if "risk" in findings:
            scores = risk.device_scores(findings, hw_summary)[["hostname", "risk", "risk_band"]]
            devices = devices.merge(scores, on="hostname", how="left")
            devices["risk"] = devices["risk"].fillna(0.0)
            devices["risk_band"] = devices["risk_band"].fillna("Low")
        else:
            devices["risk"], devices["risk_band"] = 0.0, "Low"
        columns = DEVICE_COLUMNS
        if has_hw:  # lifecycle only when EoX data exists
            columns = [c for c in HARDWARE_DEVICE_COLUMNS if c != "lifecycle" or has_lifecycle(self.inventory)]
        self.devices_model.set_frame(devices, columns)
        self.devices_view.sortByColumn(self.devices_model.column_index("risk"), Qt.DescendingOrder)
        self.devices_view._stretch_column = None if has_hw else "hostname"
        self.devices_view.horizontalHeader().setStretchLastSection(has_hw)
        fit_columns(self.devices_view, max_width=200, caps={"model": 150})
        self._filter_devices()

    def _filter_devices(self):
        frame = self.devices_model.frame
        text = self.search.text().strip().lower()
        if frame.empty:
            mask = np.zeros(0, dtype=bool)
        else:
            mask = np.ones(len(frame), dtype=bool)
            if text:
                text_mask = np.zeros(len(frame), dtype=bool)
                for col in ("hostname", "ip", "vendor", "os", "model", "serials"):
                    if col in frame:
                        text_mask |= frame[col].fillna("").astype(str).str.lower().str.contains(
                            text, regex=False).to_numpy()
                mask &= text_mask
            rule = LIFECYCLE_FILTERS.get(self.lifecycle_filter.currentText())
            if rule is not None:
                mask &= rule(frame).fillna(False).to_numpy(dtype=bool)
        self.devices_proxy.set_mask(mask)
        self.device_count.setText(f"{int(mask.sum()):,} of {len(frame):,} devices")
        if self.devices_proxy.rowCount() and not self.devices_view.currentIndex().isValid():
            self.devices_view.selectRow(0)

    def select_device(self, hostname):
        self.search.clear()
        self.lifecycle_filter.setCurrentIndex(0)
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
        badges = "&nbsp; ".join(theme.severity_badge(s, f"{int(device.get(s) or 0)} {s}")
                                for s in ("critical", "high", "medium", "low"))
        bits = []
        if not device.get("in_tenable", True):
            bits.append("<b style='color:#c62828'>Not in Tenable (AKiPS only)</b>")
        if not self.assets.empty:
            match = self.assets[self.assets["hostname"] == device["hostname"]]
            if not match.empty:
                a = match.iloc[0]
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
            f"{self._risk_html(device)}"
            f"{self._hardware_html(device['hostname'])}"
            f"<p>{badges} &nbsp; <b>{n_findings}</b> findings</p>"
        )

    def _risk_html(self, device):
        """Risk score with the parts that add up to it ("why this score")."""
        if "risk" not in self.findings:
            return ""
        parts, detail = risk.explain_device(device["hostname"], self.findings, self.hw_by_host.get(device["hostname"]))
        score = float(device.get("risk") or 0)
        band_name = risk.band(score)
        muted = theme.tokens()["text_muted"]
        items = "".join(
            f"<tr><td style='padding-right:14px'>{html.escape(label)}</td>"
            f"<td align='right'>{'+' if points >= 0 else ''}{points:g}</td></tr>" for label, points in parts)
        top = ""
        if detail:
            name, factors = detail[0]
            top = (f"<div style='color:{muted}'>Top finding: {html.escape(name)} = "
                   + " + ".join(f"{html.escape(lbl)} ({pts:g})" for lbl, pts in factors) + "</div>")
        trend = ""
        if getattr(self, "history_dir", None) is not None:
            from tenable_net import history

            points = history.device_trend(self.history_dir, device["hostname"])
            if len(points) >= 2:
                first, last = points[0][1], points[-1][1]
                arrow = "▲" if last > first else ("▼" if last < first else "→")
                trend = (f"<span style='color:{muted}'>&nbsp; trend over {len(points)} pulls: "
                         f"{first:.0f} {arrow} {last:.0f}</span>")
        return (f"<p style='margin:8px 0 2px 0'>{theme.band_badge(band_name, f'Risk {score:.0f} · {band_name}')}"
                f"{trend}&nbsp; <span style='color:{muted}'>· why this score:</span></p>"
                f"<table style='color:{muted}'>{items}</table>{top}")

    def _hardware_html(self, hostname):
        if self.inventory.empty:
            return ""
        stage, reason = self.enrichment.get(hostname, ("OK", ""))
        note = ""
        if stage not in ("OK", "Not Cisco"):
            note = (f"<p style='color:#fb8c00'>Enrichment: <b>{html.escape(stage)}</b>"
                    f"{' — ' + html.escape(reason) if reason else ''} "
                    "<span style='color:gray'>(Tools → Enrichment diagnostics)</span></p>")
        return note + self._hardware_table(hostname)

    def _hardware_table(self, hostname):
        hw = self.inventory[self.inventory["hostname"] == hostname]
        if hw.empty:
            return "<p style='color:gray'>No hardware inventory for this device.</p>"

        def text(value):  # pandas gives NaN/None for missing values; render those as empty
            return value.strip() if isinstance(value, str) else ""

        def colored(value):
            value = text(value)
            color = theme.status_color(value)
            return f"<b style='color:{color}'>{html.escape(value)}</b>" if color else html.escape(value or "—")

        cells = "padding:1px 10px 1px 0; white-space:nowrap"
        show_eox = has_lifecycle(hw)
        columns = [
            ("#", lambda r: html.escape(display("member", r["member"]))),
            ("Model", lambda r: html.escape(text(r["model"]) or "—")),
            ("Serial", lambda r: html.escape(text(r["serial"]) or "—")),
            ("Running", lambda r: html.escape(text(r["sw_version"]))),
            ("Cisco suggested", lambda r: html.escape(text(r["recommended_sw"]))),
            ("Software", lambda r: colored(r["sw_status"])),
            ("Contract", lambda r: colored(r["contract"])),
            ("Ends", lambda r: display("contract_end", r["contract_end"])),
            ("Contract #", lambda r: html.escape(text(r.get("contract_number")))),
        ]
        if show_eox:
            columns += [("Lifecycle", lambda r: colored(r["lifecycle"])),
                        ("LDoS", lambda r: display("ldos", r["ldos"]))]
        columns.append(("Source", lambda r: html.escape(text(r["source"]))))
        head = "".join(f"<th align='left' style='{cells}'>{name}</th>" for name, _fn in columns)
        body = ["<tr>" + "".join(f"<td style='{cells}'>{fn(r)}</td>" for _name, fn in columns) + "</tr>"
                for _, r in hw.iterrows()]
        extra = []
        service = next((text(v) for v in hw["service_level"] if text(v)), "")
        if service:
            extra.append(f"Service level: {html.escape(service)}")
        line_end = next((display("product_line_end", v) for v in hw["product_line_end"]
                         if display("product_line_end", v)), "")
        if line_end:
            extra.append(f"Covered product line ends: {line_end}")
        links = extra
        bulletins = [text(u) for u in hw["bulletin_url"] if text(u)]
        migrations = [text(m) for m in hw["migration_pid"] if text(m)]
        if bulletins:
            links.append(f"<a href='{html.escape(bulletins[0])}'>EoL bulletin</a>")
        if migrations:
            links.append(f"Suggested replacement: <b>{html.escape(migrations[0])}</b>")
        return (f"<table style='margin-top:6px'><tr>{head}</tr>{''.join(body)}</table>"
                + (f"<p>{' · '.join(links)}</p>" if links else ""))
