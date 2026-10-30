"""Overview tab: KPI cards, severity and vendor charts, top devices and plugins."""

import pandas as pd
from PySide6.QtCharts import (
    QBarCategoryAxis, QBarSeries, QBarSet, QChart, QChartView, QHorizontalStackedBarSeries, QValueAxis,
)
from PySide6.QtCore import QMargins, Qt, Signal
from PySide6.QtGui import QPainter, QPalette
from PySide6.QtWidgets import QGridLayout, QGroupBox, QHBoxLayout, QVBoxLayout, QWidget

from tenable_net import reports
from tenable_net.gui.models import RAW_ROLE, DataFrameModel
from tenable_net.gui.widgets import SEVERITY_COLORS, KpiCard, fit_columns, make_table, severity_color

CHART_SEVERITIES = ["critical", "high", "medium", "low"]


def _style_chart(chart, widget):
    pal = widget.palette()
    chart.setBackgroundVisible(False)
    chart.setMargins(QMargins(4, 4, 4, 4))
    chart.legend().setLabelColor(pal.color(QPalette.WindowText))
    chart.setAnimationOptions(QChart.SeriesAnimations)
    for axis in chart.axes():
        axis.setLabelsColor(pal.color(QPalette.WindowText))
        axis.setGridLineColor(pal.color(QPalette.Mid))
        axis.setLinePenColor(pal.color(QPalette.Mid))


class OverviewTab(QWidget):
    device_activated = Signal(str)            # hostname
    plugin_activated = Signal(str)            # plugin id
    severity_activated = Signal(str)          # severity

    def __init__(self, parent=None):
        super().__init__(parent)
        self.cards = {
            "findings": KpiCard("Findings", "#546e7a"),
            "devices": KpiCard("Affected devices", "#546e7a"),
            "critical": KpiCard("Critical", SEVERITY_COLORS["critical"]),
            "high": KpiCard("High", SEVERITY_COLORS["high"]),
            "exploitable": KpiCard("Exploit available", "#6a1b9a"),
            "max_vpr": KpiCard("Highest VPR", "#00838f"),
            "hardware": KpiCard("Past LDoS / not covered", "#4e342e"),
        }
        cards_row = QHBoxLayout()
        for card in self.cards.values():
            cards_row.addWidget(card)

        self.sev_chart = QChartView()
        self.vendor_chart = QChartView()
        for view in (self.sev_chart, self.vendor_chart):
            view.setRenderHint(QPainter.Antialiasing)
            view.setMinimumHeight(240)

        self.devices_model = DataFrameModel()
        self.devices_view = make_table(self.devices_model, stretch_column="os")
        self.devices_view.setSortingEnabled(False)
        self.devices_view.doubleClicked.connect(self._device_clicked)
        self.devices_view.setToolTip("Double-click to open the device")

        self.plugins_model = DataFrameModel()
        self.plugins_view = make_table(self.plugins_model, stretch_column="plugin_name")
        self.plugins_view.setSortingEnabled(False)
        self.plugins_view.doubleClicked.connect(self._plugin_clicked)
        self.plugins_view.setToolTip("Double-click to see every finding for this plugin")

        grid = QGridLayout()
        grid.addWidget(self._box("Findings by severity (click a bar to filter)", self.sev_chart), 0, 0)
        grid.addWidget(self._box("Severity by vendor", self.vendor_chart), 0, 1)
        grid.addWidget(self._box("Most exposed devices", self.devices_view), 1, 0)
        grid.addWidget(self._box("Most widespread vulnerabilities", self.plugins_view), 1, 1)
        grid.setRowStretch(0, 2)
        grid.setRowStretch(1, 3)

        layout = QVBoxLayout(self)
        layout.addLayout(cards_row)
        layout.addLayout(grid, 1)

    @staticmethod
    def _box(title, widget):
        box = QGroupBox(title)
        QVBoxLayout(box).addWidget(widget)
        return box

    def set_data(self, findings, inventory=None):
        self._set_hardware_card(inventory)
        sev = findings["severity"].astype(str)
        self.cards["findings"].set_value(len(findings))
        self.cards["devices"].set_value(findings["hostname"].nunique())
        self.cards["critical"].set_value(int((sev == "critical").sum()))
        self.cards["high"].set_value(int((sev == "high").sum()))
        self.cards["exploitable"].set_value(int((findings["exploit_available"] == True).sum()))  # noqa: E712
        max_vpr = findings["vpr"].max()
        self.cards["max_vpr"].set_value("–" if pd.isna(max_vpr) else f"{max_vpr:.1f}")

        self._severity_chart(findings)
        self._vendor_chart(findings)

        devices = reports.by_device(findings).head(10) if not findings.empty else pd.DataFrame()
        cols = ["hostname", "ip", "critical", "high", "medium", "low", "max_vpr", "os"]
        self.devices_model.set_frame(devices, cols)
        fit_columns(self.devices_view, max_width=220)

        plugins = reports.by_plugin(findings).head(10) if not findings.empty else pd.DataFrame()
        self.plugins_model.set_frame(plugins, ["severity", "devices", "max_vpr", "plugin_id", "plugin_name"])
        fit_columns(self.plugins_view, max_width=220)

    def _set_hardware_card(self, inventory):
        card = self.cards["hardware"]
        if inventory is None or inventory.empty:
            card.hide()
            return
        from tenable_net.inventory import device_summary

        devices = device_summary(inventory)
        past = int((devices["lifecycle"] == "Past LDoS").sum())
        uncovered = int((devices["contract"] == "Not covered").sum())
        card.set_value(f"{past:,} / {uncovered:,}")
        card.setToolTip(f"{past} devices past Last Date of Support, {uncovered} with hardware not under "
                        f"contract (of {len(devices)} inventoried). See the Devices tab filters.")
        card.show()

    def _severity_chart(self, findings):
        counts = findings["severity"].astype(str).value_counts()
        series = QBarSeries()
        for sev in CHART_SEVERITIES:
            bar = QBarSet(sev.title())
            bar.append(int(counts.get(sev, 0)))
            bar.setColor(severity_color(sev))
            bar.setBorderColor(severity_color(sev))
            series.append(bar)
        series.setLabelsVisible(True)
        series.setLabelsPosition(QBarSeries.LabelsPosition.LabelsOutsideEnd)
        series.clicked.connect(lambda _i, barset: self.severity_activated.emit(barset.label().lower()))
        chart = QChart()
        chart.addSeries(series)
        x = QBarCategoryAxis()
        x.append([""])
        y = QValueAxis()
        y.setLabelFormat("%d")
        y.setRange(0, max([int(counts.get(s, 0)) for s in CHART_SEVERITIES] + [1]) * 1.15)
        chart.addAxis(x, Qt.AlignBottom)
        chart.addAxis(y, Qt.AlignLeft)
        series.attachAxis(x)
        series.attachAxis(y)
        chart.legend().setAlignment(Qt.AlignBottom)
        _style_chart(chart, self)
        for bar in series.barSets():
            bar.setLabelColor(self.palette().color(QPalette.WindowText))
        self.sev_chart.setChart(chart)

    def _vendor_chart(self, findings):
        vendors = reports.by_vendor_os(findings) if not findings.empty else pd.DataFrame()
        chart = QChart()
        if not vendors.empty:
            by_vendor = vendors.groupby("vendor")[[c for c in CHART_SEVERITIES if c in vendors]].sum()
            by_vendor = by_vendor.loc[by_vendor.sum(axis=1).sort_values().index].tail(8)
            series = QHorizontalStackedBarSeries()
            for sev in CHART_SEVERITIES:
                bar = QBarSet(sev.title())
                bar.append([int(v) for v in by_vendor.get(sev, pd.Series(0, index=by_vendor.index))])
                bar.setColor(severity_color(sev))
                bar.setBorderColor(severity_color(sev))
                series.append(bar)
            chart.addSeries(series)
            y = QBarCategoryAxis()
            y.append(list(by_vendor.index))
            y.setTruncateLabels(False)
            x = QValueAxis()
            x.setLabelFormat("%d")
            chart.addAxis(y, Qt.AlignLeft)
            chart.addAxis(x, Qt.AlignBottom)
            series.attachAxis(y)
            series.attachAxis(x)
        chart.legend().setAlignment(Qt.AlignBottom)
        _style_chart(chart, self)
        self.vendor_chart.setChart(chart)

    def _device_clicked(self, index):
        frame = self.devices_model.frame
        if index.isValid() and index.row() < len(frame):
            self.device_activated.emit(str(frame.iloc[index.row()]["hostname"]))

    def _plugin_clicked(self, index):
        if index.isValid():
            pid = self.plugins_model.index(index.row(), self.plugins_model.column_index("plugin_id")).data(RAW_ROLE)
            self.plugin_activated.emit(str(pid))
