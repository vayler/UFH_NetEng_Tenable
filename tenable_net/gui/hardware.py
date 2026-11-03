"""Hardware & contracts: every chassis / stack member with model, serial, software and Cisco contract status."""

from datetime import timedelta

import numpy as np
import pandas as pd
from PySide6.QtCharts import (
    QBarCategoryAxis, QBarSeries, QBarSet, QChart, QHorizontalStackedBarSeries, QPieSeries, QValueAxis,
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QComboBox, QFileDialog, QGridLayout, QStackedWidget, QVBoxLayout, QWidget

from tenable_net.gui import charts, theme
from tenable_net.gui.models import DataFrameModel, MaskFilterProxy
from tenable_net.gui.widgets import (
    EmptyState, IconButton, KpiCard, Panel, SearchField, StatStrip, button, fit_columns, label, make_table,
)
from tenable_net.inventory import has_lifecycle

FLEET_COLUMNS = ["hostname", "member", "model", "serial", "sw_version", "recommended_sw", "sw_status", "contract",
                 "contract_end", "service_level", "lifecycle", "ldos", "source"]
_today = lambda: pd.Timestamp.now().normalize()  # noqa: E731
ROW_FILTERS = {
    "All hardware": None,
    "Not under contract": lambda d: d["contract"] == "Not covered",
    "Contract ends within 90 days": lambda d: d["contract_end"].notna()
    & (d["contract_end"] <= _today() + timedelta(days=90)),
    "Software upgrade suggested": lambda d: d["sw_status"] == "Upgrade suggested",
    "Past last day of support": lambda d: d["lifecycle"] == "Past LDoS",
    "No serial number": lambda d: d["serial"].fillna("") == "",
    "In AKiPS but not in Tenable": lambda d: d["in_tenable"] == False,  # noqa: E712
}


class HardwareView(QWidget):
    device_activated = Signal(str)
    pull_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.inventory = pd.DataFrame()

        self.cards = {
            "chassis": KpiCard("Cisco chassis / members", term="Serial", higher_is_bad=False),
            "covered": KpiCard("Under contract", term="Contract", higher_is_bad=False),
            "uncovered": KpiCard("Not under contract", term="Contract"),
            "expiring": KpiCard("Contracts ending in 90 days", term="Contract"),
            "upgrade": KpiCard("Upgrade suggested", term="Software status"),
            "past_ldos": KpiCard("Past last day of support", term="LDoS"),
        }
        for key, filter_label in (("uncovered", "Not under contract"), ("expiring", "Contract ends within 90 days"),
                                  ("upgrade", "Software upgrade suggested"), ("past_ldos", "Past last day of support")):
            self.cards[key].clicked.connect(lambda filter_label=filter_label: self.select_filter(filter_label))
        self.cards["chassis"].clicked.connect(lambda: self.select_filter("All hardware"))

        self.coverage_chart = charts.chart_view(fixed_height=200)
        self.software_chart = charts.chart_view(fixed_height=200)
        self.expiry_chart = charts.chart_view(fixed_height=200)
        chart_row = QGridLayout()
        chart_row.setSpacing(14)
        chart_row.addWidget(Panel("Contract coverage", self.coverage_chart), 0, 0)
        chart_row.addWidget(Panel("Software vs. Cisco suggestion", self.software_chart), 0, 1)
        chart_row.addWidget(Panel("Contracts ending", self.expiry_chart, "next 12 months"), 0, 2)

        self.row_filter = QComboBox()
        self.row_filter.addItems(list(ROW_FILTERS))
        self.row_filter.currentIndexChanged.connect(self._filter)
        self.search = SearchField("Filter by device, model, serial, release…")
        self.search.setMinimumWidth(260)
        self.search.textChanged.connect(self._filter)
        self.count = label("", "caption", "Muted")
        export = IconButton("export", "Export the rows shown to CSV")
        export.clicked.connect(self.export)

        self.model = DataFrameModel()
        self.proxy = MaskFilterProxy(self)
        self.proxy.setSourceModel(self.model)
        self.table = make_table(self.proxy, stretch_column="source")
        self.table.doubleClicked.connect(self._row_clicked)
        self.table.setToolTip("Double-click to open the device")
        self.table.setMinimumHeight(240)
        fleet = Panel("Fleet", self.table, flush=True)
        self.fleet_panel = fleet
        for w in (self.count, self.search, self.row_filter, export):
            fleet.add_action(w)

        content = QWidget()
        cl = QVBoxLayout(content)
        cl.setContentsMargins(18, 16, 18, 10)
        cl.setSpacing(14)
        self.strip = StatStrip(list(self.cards.values()))
        cl.addWidget(self.strip)
        cl.addLayout(chart_row)
        cl.addWidget(fleet, 1)

        pull = button("Pull from Tenable…", "primary", "pull")
        pull.clicked.connect(self.pull_requested.emit)
        empty = EmptyState("hardware", "No hardware inventory yet",
                           "Pull with <b>Hardware inventory</b> ticked to see models, serials, software and Cisco "
                           "contract status for every chassis and stack member.", [pull])

        self.stack = QStackedWidget()
        self.stack.addWidget(empty)
        self.stack.addWidget(content)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.stack)

    def set_data(self, inventory):
        self.inventory = inventory if inventory is not None else pd.DataFrame()
        if self.inventory.empty:
            self.stack.setCurrentIndex(0)
            return
        self.stack.setCurrentIndex(1)
        inv = self.inventory
        eox = bool(has_lifecycle(inv))
        cisco_rows = inv[inv["vendor"] == "Cisco"]
        n = len(cisco_rows)
        covered = int((cisco_rows["contract"] == "Covered").sum())
        self.cards["chassis"].set_value(n)
        self.cards["chassis"].delta.setText(f"of {len(inv):,} inventoried" if len(inv) != n else "")
        self.cards["covered"].set_value(f"{covered / n:.0%}" if n else "–")
        self.cards["covered"].delta.setText(f"{covered:,} of {n:,}" if n else "")
        self.cards["uncovered"].set_value(int((cisco_rows["contract"] == "Not covered").sum()))
        soon = cisco_rows["contract_end"].notna() & (cisco_rows["contract_end"] <= _today() + timedelta(days=90))
        self.cards["expiring"].set_value(int(soon.sum()))
        self.cards["upgrade"].set_value(int((cisco_rows["sw_status"] == "Upgrade suggested").sum()))
        self.cards["past_ldos"].setVisible(eox)
        if eox:
            self.cards["past_ldos"].set_value(int((cisco_rows["lifecycle"] == "Past LDoS").sum()))
        columns = [c for c in FLEET_COLUMNS if c not in ("lifecycle", "ldos") or eox]
        self.model.set_frame(inv, columns)
        self.table.sortByColumn(self.model.column_index("hostname"), Qt.AscendingOrder)
        fit_columns(self.table, max_width=180, caps={"hostname": 220})
        self._coverage(cisco_rows)
        self._software(cisco_rows)
        self._expiry(cisco_rows)
        self._filter()

    def select_filter(self, filter_label):
        if filter_label in ROW_FILTERS:
            self.search.clear()
            self.row_filter.setCurrentText(filter_label)

    def _filter(self, *_):
        active = self.row_filter.currentIndex() > 0
        if bool(self.row_filter.property("active")) != active:
            self.row_filter.setProperty("active", active)
            theme.repolish(self.row_filter)
        frame = self.model.frame
        if frame.empty:
            self.proxy.set_mask(np.zeros(0, dtype=bool))
            self.count.setText("")
            return
        mask = np.ones(len(frame), dtype=bool)
        rule = ROW_FILTERS.get(self.row_filter.currentText())
        if rule is not None:
            mask &= rule(frame).fillna(False).to_numpy(dtype=bool)
        text = self.search.text().strip().lower()
        if text:
            cols = [c for c in ("hostname", "model", "serial", "sw_version", "recommended_sw", "akips_device")
                    if c in frame]
            hay = frame[cols].fillna("").astype(str).agg(" ".join, axis=1).str.lower()
            mask &= hay.str.contains(text, regex=False).to_numpy()
        self.proxy.set_mask(mask)
        shown = int(mask.sum())
        self.count.setText(f"{shown:,} chassis" if shown == len(frame) else f"{shown:,} of {len(frame):,}")
        self.fleet_panel.set_subtitle("")

    def _row_clicked(self, index):
        if index.isValid():
            row = self.model.frame.iloc[self.proxy.mapToSource(index).row()]
            self.device_activated.emit(str(row["hostname"]))

    def export(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export hardware", "hardware_contracts.csv", "CSV (*.csv)")
        if path:
            frame = self.model.frame
            rows = [self.proxy.source_row(r) for r in range(self.proxy.rowCount())]
            frame.iloc[rows].to_csv(path, index=False)

    def refresh_theme(self):
        if not self.inventory.empty:
            cisco_rows = self.inventory[self.inventory["vendor"] == "Cisco"]
            self._coverage(cisco_rows)
            self._software(cisco_rows)
            self._expiry(cisco_rows)

    # ---- charts -------------------------------------------------------------------------------
    def _coverage(self, rows):
        t = theme.tokens()
        counts = rows["contract"].replace("", "Unknown").value_counts()
        series = QPieSeries()
        series.setHoleSize(0.62)
        series.setPieSize(0.82)
        colors = {"Covered": t["dot_good"], "Not covered": t["dot_bad"], "Unknown": t["dot_neutral"],
                  "No serial": t["border_strong"]}
        for name in ("Covered", "Not covered", "Unknown", "No serial"):
            if counts.get(name, 0):
                s = series.append(f"{name}  {counts[name]}", int(counts[name]))
                s.setColor(QColor(colors[name]))
                s.setBorderColor(QColor(t["surface"]))
                s.setBorderWidth(2)
        series.clicked.connect(lambda s: self.select_filter("Not under contract") if s.label().startswith("Not covered")
                               else None)
        chart = QChart()
        chart.addSeries(series)
        chart.legend().setAlignment(Qt.AlignRight)
        charts.style_chart(chart)
        self.coverage_chart.setChart(chart)

    def _software(self, rows):
        """One horizontal bar per status, each in its own colour, labelled on the axis (no legend needed)."""
        t = theme.tokens()
        order = [("On suggested release", t["dot_good"]), ("Upgrade suggested", theme.SEVERITY_COLORS["high"]),
                 ("Newer than suggested", t["accent"]), ("No suggestion", t["dot_neutral"])]
        counts = rows["sw_status"].value_counts()
        series = QHorizontalStackedBarSeries()
        for i, (name, color) in enumerate(order):
            bar = QBarSet(name)
            bar.append([int(counts.get(name, 0)) if j == i else 0 for j in range(len(order))])
            charts.no_border(bar, color)
            series.append(bar)
        series.setBarWidth(0.56)
        series.setLabelsVisible(True)
        series.clicked.connect(lambda _i, b: self.select_filter("Software upgrade suggested")
                               if b.label() == "Upgrade suggested" else None)
        chart = QChart()
        chart.addSeries(series)
        y = QBarCategoryAxis()
        y.append([name for name, _c in order])
        y.setTruncateLabels(False)
        x = QValueAxis()
        x.setLabelFormat("%d")
        x.setTickCount(5)
        x.setRange(0, max([int(counts.get(n, 0)) for n, _c in order] + [1]) * 1.15)
        chart.addAxis(y, Qt.AlignLeft)
        chart.addAxis(x, Qt.AlignBottom)
        series.attachAxis(y)
        series.attachAxis(x)
        chart.legend().setVisible(False)
        charts.style_chart(chart)
        for bar in series.barSets():
            bar.setLabelColor(QColor("#FFFFFF"))
        self.software_chart.setChart(chart)

    def _expiry(self, rows):
        start = _today().replace(day=1)
        months = [start + pd.DateOffset(months=i) for i in range(12)]
        ends = rows["contract_end"].dropna()
        values = [int(((ends >= m) & (ends < m + pd.DateOffset(months=1))).sum()) for m in months]
        bar = QBarSet("Contracts ending")
        bar.append(values)
        charts.no_border(bar, theme.tokens()["accent"])
        series = QBarSeries()
        series.append(bar)
        series.setBarWidth(0.6)
        chart = QChart()
        chart.addSeries(series)
        x = QBarCategoryAxis()
        x.append([f"{m:%b}" for m in months])
        x.setTruncateLabels(False)
        y = QValueAxis()
        y.setLabelFormat("%d")
        y.setTickCount(4)
        y.setRange(0, max(values + [1]) * 1.2)
        chart.addAxis(x, Qt.AlignBottom)
        chart.addAxis(y, Qt.AlignLeft)
        series.attachAxis(x)
        series.attachAxis(y)
        chart.legend().setVisible(False)
        charts.style_chart(chart)
        self.expiry_chart.setChart(chart)
