"""Devices: searchable device list on the left; the selected device's score, hardware and findings on the right."""

import html
from datetime import timedelta

import numpy as np
import pandas as pd
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QComboBox, QFrame, QHBoxLayout, QTextBrowser, QVBoxLayout, QWidget

from tenable_net import reports, risk
from tenable_net.gui import theme
from tenable_net.gui.findings import FindingsPanel
from tenable_net.gui.models import DataFrameModel, MaskFilterProxy, display
from tenable_net.gui.widgets import SearchField, Splitter, divider, fit_columns, label, make_table
from tenable_net.inventory import device_summary, has_lifecycle
from tenable_net.normalize import vendor_of

DEVICE_COLUMNS = ["hostname", "risk", "critical", "high", "medium", "low", "ip", "vendor"]
# Hardware mode has more columns, so only critical/high counts are listed (the header shows all four).
HARDWARE_DEVICE_COLUMNS = ["hostname", "risk", "critical", "high", "contract", "sw_status", "model", "lifecycle"]
DEVICE_FINDING_COLUMNS = [
    "risk", "severity", "plugin_name", "vpr", "exploit_available", "cves", "plugin_id", "port", "days_open",
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


class DeviceHeader(QTextBrowser):
    """The selected device's name, score breakdown and hardware, as selectable rich text."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setOpenExternalLinks(True)
        self.document().setDocumentMargin(18)
        self._html = ""

    def setText(self, text):
        from tenable_net.gui.widgets import detail_css

        self._html = text
        self.document().setDefaultStyleSheet(detail_css())
        self.setHtml(text)

    def text(self):
        return self._html


class DevicesTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.findings = pd.DataFrame()
        self.assets = pd.DataFrame()
        self.inventory = pd.DataFrame()
        self.enrichment = {}

        self.search = SearchField("Filter by name, IP, model, serial…")
        self.search.textChanged.connect(self._filter_devices)
        self.lifecycle_filter = QComboBox()
        self.lifecycle_filter.addItems(list(LIFECYCLE_FILTERS))
        self.lifecycle_filter.setToolTip("Hardware, contract and lifecycle filters (needs inventory data)")
        self.lifecycle_filter.currentIndexChanged.connect(self._filter_devices)
        self.devices_model = DataFrameModel()
        self.devices_proxy = MaskFilterProxy(self)
        self.devices_proxy.setSourceModel(self.devices_model)
        self.devices_view = make_table(self.devices_proxy, stretch_column="hostname")
        self.devices_view.selectionModel().currentRowChanged.connect(self._on_device)
        self.device_count = label("", "caption", "Muted")

        bar = QFrame()
        bar.setObjectName("Toolbar")
        filters = QHBoxLayout(bar)
        filters.setContentsMargins(12, 10, 8, 10)
        filters.setSpacing(6)
        filters.addWidget(self.search, 3)
        filters.addWidget(self.lifecycle_filter, 2)
        footer = QHBoxLayout()
        footer.setContentsMargins(14, 6, 14, 0)
        footer.addWidget(self.device_count)
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(0)
        left_layout.addWidget(bar)
        left_layout.addWidget(divider())
        left_layout.addWidget(self.devices_view, 1)
        left_layout.addLayout(footer)

        self.header = DeviceHeader()
        self.panel = FindingsPanel(DEVICE_FINDING_COLUMNS)
        right = Splitter(Qt.Vertical, line=True)
        right.addWidget(self.header)
        right.addWidget(self.panel)
        right.setStretchFactor(0, 2)
        right.setStretchFactor(1, 3)
        right.setSizes([390, 460])  # a device has few findings; its score and hardware come first
        self.right = right

        splitter = Splitter(Qt.Horizontal, line=True)
        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 3)
        splitter.setSizes([560, 640])
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
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
        fit_columns(self.devices_view, max_width=200, caps={"model": 150, "hostname": 210})
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
        shown, total = int(mask.sum()), len(frame)
        self.device_count.setText(f"{shown:,} devices" if shown == total else f"{shown:,} of {total:,} devices")
        active = self.lifecycle_filter.currentIndex() > 0
        if bool(self.lifecycle_filter.property("active")) != active:
            self.lifecycle_filter.setProperty("active", active)
            theme.repolish(self.lifecycle_filter)
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

    def refresh_theme(self):
        """Re-render the selected device and finding (their colours are baked into the rich text), keeping
        the finding that is selected."""
        current = self.devices_view.currentIndex()
        if current.isValid():
            device = self.devices_model.frame.iloc[self.devices_proxy.mapToSource(current).row()]
            self.header.setText(self._header_html(device, self.panel.model.rowCount()))
        self.panel.refresh_theme()

    def reset_filters(self):
        self.search.clear()
        self.lifecycle_filter.setCurrentIndex(0)

    def _on_device(self, current, _previous):
        if not current.isValid():
            return
        device = self.devices_model.frame.iloc[self.devices_proxy.mapToSource(current).row()]
        hostname = device["hostname"]
        rows = self.findings[self.findings["hostname"] == hostname] if not self.findings.empty else self.findings
        self.panel.set_frame(rows)
        self.header.setText(self._header_html(device, len(rows)))

    def _header_html(self, device, n_findings):
        t = theme.tokens()
        counts = " &nbsp; ".join(theme.severity_badge(s, f"{int(device.get(s) or 0)} {s}")
                                 for s in ("critical", "high", "medium", "low"))
        bits = [html.escape(str(device.get("ip") or "")), html.escape(str(device.get("os") or "Unknown OS"))]
        if not self.assets.empty:
            match = self.assets[self.assets["hostname"] == device["hostname"]]
            if not match.empty:
                a = match.iloc[0]
                if a.get("system_type"):
                    bits.append(html.escape(str(a["system_type"])))
                if display("last_seen", a.get("last_seen")):
                    bits.append(f"last seen {display('last_seen', a.get('last_seen'))}")
                if a.get("tags"):
                    bits.append(html.escape(str(a["tags"])))
        warning = ""
        if not device.get("in_tenable", True):
            warning = (f"<p><span style='color:{t['bad']}; font-weight:600'>Not in Tenable (AKiPS only)</span>"
                       f" <span class='muted'>— Tenable has never scanned this device.</span></p>")
        return (
            f"<h2>{html.escape(str(device['hostname']))}</h2>"
            f"<p class='muted'>{' · '.join(b for b in bits if b)}</p>{warning}"
            f"<p style='margin-top:10px'>{counts} &nbsp;<span class='muted'>· {n_findings} findings</span></p>"
            f"{self._risk_html(device)}"
            f"{self._hardware_html(device['hostname'])}"
        )

    def _risk_html(self, device):
        """Risk score with the parts that add up to it ("why this score")."""
        if "risk" not in self.findings:
            return ""
        # (the top finding's own breakdown is in the findings table and detail pane just below)
        parts, _detail = risk.explain_device(device["hostname"], self.findings, self.hw_by_host.get(device["hostname"]))
        score = float(device.get("risk") or 0)
        band_name = risk.band(score)
        items = "".join(
            f"<tr><td class='k'>{html.escape(label_)}</td>"
            f"<td align='right'>{'+' if points >= 0 else ''}{points:g}</td></tr>" for label_, points in parts)
        trend = ""
        if getattr(self, "history_dir", None) is not None:
            from tenable_net import history

            points = history.device_trend(self.history_dir, device["hostname"])
            if len(points) >= 2:
                first, last = points[0][1], points[-1][1]
                arrow = "▲" if last > first else ("▼" if last < first else "→")
                trend = (f" &nbsp;<span class='muted'>· over {len(points)} pulls: "
                         f"{first:.0f} {arrow} {last:.0f}</span>")
        return (f"<h4>Why this score</h4>"
                f"<p>{theme.band_badge(band_name, f'Risk {score:.0f} · {band_name}')}{trend}</p>"
                f"<table cellspacing='0'>{items}</table>")

    def _hardware_html(self, hostname):
        if self.inventory.empty:
            return ""
        stage, reason = self.enrichment.get(hostname, ("OK", ""))
        note = ""
        if stage not in ("OK", "Not Cisco"):
            t = theme.tokens()
            note = (f"<p><span style='color:{t['warn']}'>Enrichment: <b>{html.escape(stage)}</b></span>"
                    f"{' — ' + html.escape(reason) if reason else ''} "
                    "<span class='muted'>(see Diagnostics)</span></p>")
        return "<h4>Hardware</h4>" + note + self._hardware_table(hostname)

    def _hardware_table(self, hostname):
        hw = self.inventory[self.inventory["hostname"] == hostname]
        if hw.empty:
            return "<p class='muted'>No hardware inventory for this device.</p>"

        def text(value):  # pandas gives NaN/None for missing values; render those as empty
            return value.strip() if isinstance(value, str) else ""

        def status(value):
            value = text(value)
            return theme.status_badge(html.escape(value)) if value else "—"

        cell = "padding:4px 16px 4px 0"
        keep = cell + "; white-space:nowrap"  # model / serial never break mid-token
        show_eox = has_lifecycle(hw)

        def two_lines(badge, detail):
            return badge + (f"<br><span class='muted'>{detail}</span>" if detail else "")

        def software(r):
            running, suggested = html.escape(text(r["sw_version"])), html.escape(text(r["recommended_sw"]))
            detail = f"{running} → {suggested}" if running and suggested else running or suggested
            return two_lines(status(r["sw_status"]), detail)

        def contract(r):
            parts = [f"until {display('contract_end', r['contract_end'])}" if display("contract_end", r["contract_end"])
                     else "", f"#{html.escape(text(r.get('contract_number')))}" if text(r.get("contract_number")) else ""]
            return two_lines(status(r["contract"]), " · ".join(p for p in parts if p))

        columns = [
            ("#", keep, lambda r: html.escape(display("member", r["member"]))),
            ("Model", keep, lambda r: html.escape(text(r["model"]) or "—")),
            ("Serial", keep, lambda r: html.escape(text(r["serial"]) or "—")),
            ("Software (running → Cisco suggested)", cell, software),
            ("Contract", cell, contract),
        ]
        if show_eox:
            columns.append(("Lifecycle", cell, lambda r: two_lines(
                status(r["lifecycle"]), f"LDoS {display('ldos', r['ldos'])}" if display("ldos", r["ldos"]) else "")))
        muted = theme.tokens()["text_muted"]
        head = "".join(f"<td style='{style}; color:{muted}'>{name}</td>" for name, style, _fn in columns)
        body = ["<tr>" + "".join(f"<td style='{style}'>{fn(r)}</td>" for _name, style, fn in columns) + "</tr>"
                for _, r in hw.iterrows()]
        links = []
        service = next((text(v) for v in hw["service_level"] if text(v)), "")
        if service:
            links.append(f"Service level: {html.escape(service)}")
        line_end = next((display("product_line_end", v) for v in hw["product_line_end"]
                         if display("product_line_end", v)), "")
        if line_end:
            links.append(f"Covered product line ends: {line_end}")
        bulletins = [text(u) for u in hw["bulletin_url"] if text(u)]
        migrations = [text(m) for m in hw["migration_pid"] if text(m)]
        if bulletins:
            links.append(f"<a href='{html.escape(bulletins[0])}'>EoL bulletin</a>")
        if migrations:
            links.append(f"Suggested replacement: <b>{html.escape(migrations[0])}</b>")
        return (f"<table cellspacing='0'><tr>{head}</tr>{''.join(body)}</table>"
                + (f"<p class='muted' style='margin-top:6px'>{' · '.join(links)}</p>" if links else ""))
