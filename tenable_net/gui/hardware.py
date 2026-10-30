"""Hardware & Contracts: every chassis / stack member with model, serial, software and Cisco contract status."""

from datetime import timedelta

import numpy as np
import pandas as pd
from PySide6.QtCharts import (
    QBarCategoryAxis, QBarSeries, QBarSet, QChart, QChartView, QHorizontalStackedBarSeries, QPieSeries, QValueAxis,
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QPainter
from PySide6.QtWidgets import (
    QComboBox, QFileDialog, QGridLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QStackedWidget, QVBoxLayout,
    QWidget,
)

from tenable_net.gui import theme
from tenable_net.gui.models import DataFrameModel, MaskFilterProxy
from tenable_net.gui.overview import _section, _style_chart
from tenable_net.gui.widgets import KpiCard, fit_columns, make_table
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
            "chassis": KpiCard("Cisco chassis / stack members", term="Serial", higher_is_bad=False),
            "covered": KpiCard("Under contract", term="Contract", higher_is_bad=False),
            "uncovered": KpiCard("Not under contract", term="Contract"),
            "expiring": KpiCard("Contracts ending in 90 days", term="Contract"),
            "upgrade": KpiCard("Upgrade suggested", term="Software status"),
            "past_ldos": KpiCard("Past last day of support", term="LDoS"),
        }
        for key, label in (("uncovered", "Not under contract"), ("expiring", "Contract ends within 90 days"),
                           ("upgrade", "Software upgrade suggested"), ("past_ldos", "Past last day of support")):
            self.cards[key].clicked.connect(lambda label=label: self.row_filter.setCurrentText(label))
        cards = QHBoxLayout()
        cards.setSpacing(12)
        for card in self.cards.values():
            cards.addWidget(card)

        self.coverage_chart, self.software_chart, self.expiry_chart = QChartView(), QChartView(), QChartView()
        for view in (self.coverage_chart, self.software_chart, self.expiry_chart):
            view.setRenderHint(QPainter.Antialiasing)
            view.setFixedHeight(200)
            view.setStyleSheet("background: transparent; border: none;")
        charts = QGridLayout()
        charts.setSpacing(14)
        charts.addWidget(_section("Contract coverage", self.coverage_chart), 0, 0)
        charts.addWidget(_section("Software vs. Cisco suggestion", self.software_chart), 0, 1)
        charts.addWidget(_section("Contracts ending, next 12 months", self.expiry_chart), 0, 2)

        self.row_filter = QComboBox()
        self.row_filter.addItems(list(ROW_FILTERS))
        self.row_filter.currentIndexChanged.connect(self._filter)
        self.search = QLineEdit(placeholderText="Filter by device, model, serial, release…", clearButtonEnabled=True)
        self.search.textChanged.connect(self._filter)
        self.count = QLabel()
        self.count.setObjectName("Muted")
        export = QPushButton("Export…")
        export.clicked.connect(self.export)
        filters = QHBoxLayout()
        filters.addWidget(self.row_filter)
        filters.addWidget(self.search, 1)
        filters.addWidget(self.count)
        filters.addWidget(export)

        self.model = DataFrameModel()
        self.proxy = MaskFilterProxy(self)
        self.proxy.setSourceModel(self.model)
        self.table = make_table(self.proxy, stretch_column="source")
        self.table.doubleClicked.connect(self._row_clicked)
        self.table.setToolTip("Double-click to open the device")

        content = QWidget()
        cl = QVBoxLayout(content)
        cl.setContentsMargins(0, 0, 0, 0)
        cl.setSpacing(12)
        cl.addLayout(cards)
        cl.addLayout(charts)
        cl.addLayout(filters)
        cl.addWidget(self.table, 1)
        self.table.setMinimumHeight(260)

        empty = QWidget()
        el = QVBoxLayout(empty)
        el.addStretch(1)
        msg = QLabel("<h3>No hardware inventory yet</h3>Pull with <b>Hardware inventory</b> ticked to see models, "
                     "serials, software and Cisco contract status for every chassis and stack member.")
        msg.setWordWrap(True)
        msg.setAlignment(Qt.AlignCenter)
        pull = QPushButton("Pull from Tenable…")
        pull.setObjectName("Primary")
        pull.clicked.connect(self.pull_requested.emit)
        el.addWidget(msg)
        el.addWidget(pull, alignment=Qt.AlignCenter)
        el.addStretch(2)

        self.stack = QStackedWidget()
        self.stack.addWidget(empty)
        self.stack.addWidget(content)
        QVBoxLayout(self).addWidget(self.stack)
        self.layout().setContentsMargins(0, 0, 0, 0)

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
        fit_columns(self.table, max_width=180)
        self._coverage(cisco_rows)
        self._software(cisco_rows)
        self._expiry(cisco_rows)
        self._filter()

    def select_filter(self, label):
        if label in ROW_FILTERS:
            self.search.clear()
            self.row_filter.setCurrentText(label)

    def _filter(self, *_):
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
        self.count.setText(f"{int(mask.sum()):,} of {len(frame):,}")

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

    # ---- charts -------------------------------------------------------------------------------
    def _coverage(self, rows):
        t = theme.tokens()
        counts = rows["contract"].replace("", "Unknown").value_counts()
        series = QPieSeries()
        series.setHoleSize(0.55)
        colors = {"Covered": t["good"], "Not covered": t["bad"], "Unknown": t["neutral"], "No serial": t["border_strong"]}
        for label in ("Covered", "Not covered", "Unknown", "No serial"):
            if counts.get(label, 0):
                s = series.append(f"{label} {counts[label]}", int(counts[label]))
                s.setColor(QColor(colors[label]))
                s.setBorderColor(QColor(t["surface"]))
        series.clicked.connect(lambda s: self.select_filter("Not under contract") if s.label().startswith("Not covered")
                               else None)
        chart = QChart()
        chart.addSeries(series)
        chart.legend().setAlignment(Qt.AlignRight)
        _style_chart(chart)
        self.coverage_chart.setChart(chart)

    def _software(self, rows):
        """One horizontal bar per status, each in its own colour, labelled on the axis (no legend needed)."""
        t = theme.tokens()
        order = [("On suggested release", t["good"]), ("Upgrade suggested", theme.SEVERITY_COLORS["high"]),
                 ("Newer than suggested", t["brand"]), ("No suggestion", t["neutral"])]
        counts = rows["sw_status"].value_counts()
        series = QHorizontalStackedBarSeries()
        for i, (label, color) in enumerate(order):
            bar = QBarSet(label)
            bar.append([int(counts.get(label, 0)) if j == i else 0 for j in range(len(order))])
            bar.setColor(QColor(color))
            bar.setBorderColor(QColor(color))
            series.append(bar)
        series.setBarWidth(0.6)
        series.setLabelsVisible(True)
        series.clicked.connect(lambda _i, b: self.select_filter("Software upgrade suggested")
                               if b.label() == "Upgrade suggested" else None)
        chart = QChart()
        chart.addSeries(series)
        y = QBarCategoryAxis()
        y.append([label for label, _c in reversed(order)][::-1])
        y.setTruncateLabels(False)
        x = QValueAxis()
        x.setLabelFormat("%d")
        x.setRange(0, max([int(counts.get(lbl, 0)) for lbl, _c in order] + [1]) * 1.15)
        chart.addAxis(y, Qt.AlignLeft)
        chart.addAxis(x, Qt.AlignBottom)
        series.attachAxis(y)
        series.attachAxis(x)
        chart.legend().setVisible(False)
        _style_chart(chart)
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
        bar.setColor(QColor(theme.tokens()["brand"]))
        series = QBarSeries()
        series.append(bar)
        series.setBarWidth(0.7)
        chart = QChart()
        chart.addSeries(series)
        x = QBarCategoryAxis()
        x.append([f"{m:%b}" for m in months])
        x.setTruncateLabels(False)
        y = QValueAxis()
        y.setLabelFormat("%d")
        y.setRange(0, max(values + [1]) * 1.2)
        chart.addAxis(x, Qt.AlignBottom)
        chart.addAxis(y, Qt.AlignLeft)
        series.attachAxis(x)
        series.attachAxis(y)
        chart.legend().setVisible(False)
        _style_chart(chart)
        self.expiry_chart.setChart(chart)
