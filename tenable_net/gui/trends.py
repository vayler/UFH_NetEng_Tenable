"""Trends: how exposure changes from pull to pull, built from the history snapshots."""

import pandas as pd
from PySide6.QtCharts import (
    QAreaSeries, QBarCategoryAxis, QBarSeries, QBarSet, QChart, QDateTimeAxis, QLineSeries, QValueAxis,
)
from PySide6.QtCore import QDateTime, Qt, Signal
from PySide6.QtGui import QColor, QPen
from PySide6.QtWidgets import QGridLayout, QHBoxLayout, QVBoxLayout, QWidget

from tenable_net import history
from tenable_net.gui import charts, theme
from tenable_net.gui.models import DataFrameModel
from tenable_net.gui.widgets import Panel, Segmented, fit_columns, label, make_table, severity_color

RANGES = {"30 days": 30, "90 days": 90, "All history": None}


def _ms(ts):
    return QDateTime.fromSecsSinceEpoch(int(pd.Timestamp(ts).timestamp())).toMSecsSinceEpoch()


class TrendsView(QWidget):
    view_requested = Signal(str, dict)

    def __init__(self, cache_dir, parent=None):
        super().__init__(parent)
        self.cache_dir = cache_dir
        top = QHBoxLayout()
        top.setSpacing(12)
        self.range = Segmented(list(RANGES), current="90 days")
        self.range.currentIndexChanged.connect(self.reload)
        self.summary = label("", "body", "Muted", wrap=True)
        self.summary.setTextFormat(Qt.RichText)
        top.addWidget(self.range)
        top.addWidget(self.summary, 1)

        self.open_chart = charts.chart_view(min_height=250)
        self.flow_chart = charts.chart_view(min_height=250)
        self.fleet_chart = charts.chart_view(min_height=250)
        self.ttf_model = DataFrameModel()
        self.ttf_view = make_table(self.ttf_model, stretch_column="severity")
        self.ttf_view.setSortingEnabled(False)

        grid = QGridLayout()
        grid.setSpacing(14)
        grid.addWidget(Panel("Open findings by severity", self.open_chart, "Stacked: the top line is everything "
                                                                           "still open"), 0, 0)
        grid.addWidget(Panel("New vs. fixed per pull", self.flow_chart, "Above zero: new findings. Below: findings "
                                                                        "that went away"), 0, 1)
        grid.addWidget(Panel("Fleet risk and devices at critical / high risk", self.fleet_chart), 1, 0)
        grid.addWidget(Panel("Time to fix", self.ttf_view, "Days from first found to the first pull where it was "
                                                           "gone", flush=True), 1, 1)
        self.empty = label("", "body", "Muted", wrap=True)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 14, 18, 12)
        layout.setSpacing(12)
        layout.addLayout(top)
        layout.addWidget(self.empty)
        layout.addLayout(grid, 1)
        self.reload()

    def reload(self, *_):
        days = RANGES.get(self.range.currentText())
        data = history.series(self.cache_dir, days)
        n = len(history.list_snapshots(self.cache_dir))
        self.empty.setVisible(n < 2)
        self.empty.setText(f"{n} pull{'s' if n != 1 else ''} recorded so far. Trends fill in as you pull "
                           "again: each pull adds a point.")
        if not data.empty:
            first, last = data.iloc[0], data.iloc[-1]
            open_now, open_then = sum(last[s] for s in history.SEVERITIES), sum(first[s] for s in history.SEVERITIES)
            change = open_now - open_then
            t = theme.tokens()
            color = t["good"] if change < 0 else (t["bad"] if change > 0 else t["text_muted"])
            self.summary.setText(f"{len(data)} pulls from {first['at']:%d %b %Y} to {last['at']:%d %b %Y} · "
                                 f"open findings {open_then:,} → <span style='color:{t['text']}'>{open_now:,}</span>"
                                 f" <span style='color:{color}'>({change:+,})</span>")
        else:
            self.summary.setText("")
        self._open_chart(data)
        self._flow_chart(data)
        self._fleet_chart(data)
        ttf = history.time_to_fix(self.cache_dir)
        if not ttf.empty:
            ttf = ttf.assign(mean_days=ttf["mean_days"].round(1), median_days=ttf["median_days"].round(1))
        self.ttf_model.set_frame(ttf, ["severity", "fixed", "mean_days", "median_days"])
        fit_columns(self.ttf_view)

    def refresh_theme(self):
        self.reload()

    def _time_axis(self, chart, data):
        axis = QDateTimeAxis()
        axis.setFormat("dd MMM")
        if not data.empty:
            lo, hi = _ms(data["at"].min()), _ms(data["at"].max())
            if lo == hi:
                hi = lo + 86_400_000
            axis.setRange(QDateTime.fromMSecsSinceEpoch(lo), QDateTime.fromMSecsSinceEpoch(hi))
        axis.setTickCount(min(max(len(data), 2), 7))
        chart.addAxis(axis, Qt.AlignBottom)
        return axis

    def _open_chart(self, data):
        chart = QChart()
        x = self._time_axis(chart, data)
        y = QValueAxis()
        y.setLabelFormat("%d")
        y.setTickCount(5)
        chart.addAxis(y, Qt.AlignLeft)
        lower = None
        running = [0] * len(data)
        for sev in reversed(history.SEVERITIES):  # low at the bottom, critical on top
            # QAreaSeries doesn't own its boundary lines: parent them to the chart so Python can't free them.
            upper = QLineSeries(chart)
            for i, (ts, v) in enumerate(zip(data["at"], data[sev])):
                running[i] += int(v)
                upper.append(_ms(ts), running[i])
            area = QAreaSeries(upper, lower) if lower is not None else QAreaSeries(upper)
            area.setName(sev.title())
            c = severity_color(sev)
            fill = QColor(c)
            fill.setAlphaF(0.55)
            area.setColor(fill)
            area.setBorderColor(c)
            pen = area.pen()
            pen.setWidthF(1.5)
            pen.setColor(c)
            area.setPen(pen)
            chart.addSeries(area)
            area.attachAxis(x)
            area.attachAxis(y)
            lower = QLineSeries(chart)
            for i, ts in enumerate(data["at"]):
                lower.append(_ms(ts), running[i])
        y.setRange(0, max(running + [1]) * 1.1)
        y.applyNiceNumbers()
        chart.legend().setAlignment(Qt.AlignBottom)
        charts.style_chart(chart)
        self.open_chart.setChart(chart)

    def _flow_chart(self, data):
        chart = QChart()
        flow = data.dropna(subset=["new"]) if not data.empty else data
        series = QBarSeries()
        new, fixed = QBarSet("New"), QBarSet("Fixed")
        t = theme.tokens()
        charts.no_border(new, theme.SEVERITY_COLORS["critical"])
        charts.no_border(fixed, t["dot_good"])
        for v in flow["new"] if not flow.empty else []:
            new.append(int(v))
        for v in flow["fixed"] if not flow.empty else []:
            fixed.append(-int(v))
        series.append(new)
        series.append(fixed)
        series.setBarWidth(0.7)
        chart.addSeries(series)
        x = QBarCategoryAxis()
        x.append([f"{ts:%d %b}" for ts in flow["at"]] if not flow.empty else [""])
        x.setTruncateLabels(False)
        y = QValueAxis()
        y.setLabelFormat("%d")
        hi = max([int(v) for v in flow["new"]] + [1]) if not flow.empty else 1
        lo = max([int(v) for v in flow["fixed"]] + [1]) if not flow.empty else 1
        y.setRange(-lo * 1.15, hi * 1.15)
        y.applyNiceNumbers()
        chart.addAxis(x, Qt.AlignBottom)
        chart.addAxis(y, Qt.AlignLeft)
        series.attachAxis(x)
        series.attachAxis(y)
        series.clicked.connect(lambda _i, barset: self.view_requested.emit("findings", {"changed": True})
                               if barset.label() == "New" else None)
        chart.legend().setAlignment(Qt.AlignBottom)
        charts.style_chart(chart)
        self.flow_chart.setChart(chart)

    def _fleet_chart(self, data):
        chart = QChart()
        x = self._time_axis(chart, data)
        y = QValueAxis()
        y.setRange(0, 100)
        y.setLabelFormat("%d")
        y.setTickCount(5)
        y.setTitleText("Fleet risk")
        y2 = QValueAxis()
        y2.setLabelFormat("%d")
        y2.setTickCount(5)
        y2.setTitleText("Devices")
        chart.addAxis(y, Qt.AlignLeft)
        chart.addAxis(y2, Qt.AlignRight)
        fleet, devices = QLineSeries(), QLineSeries()
        fleet.setName("Fleet risk (0-100)")
        devices.setName("Devices at critical / high risk")
        for ts, f, d in zip(data["at"], data["fleet"], data["at_risk"]) if not data.empty else []:
            fleet.append(_ms(ts), float(f))
            devices.append(_ms(ts), int(d))
        fleet_pen = QPen(QColor(theme.tokens()["accent"]), 2.2)
        devices_pen = QPen(QColor(theme.SEVERITY_COLORS["high"]), 2, Qt.DashLine)
        for s, pen in ((fleet, fleet_pen), (devices, devices_pen)):
            pen.setCapStyle(Qt.RoundCap)
            s.setPen(pen)
            s.setPointsVisible(True)
            chart.addSeries(s)
            s.attachAxis(x)
        fleet.attachAxis(y)
        devices.attachAxis(y2)
        y2.setRange(0, max([int(v) for v in data["at_risk"]] + [1]) * 1.2 if not data.empty else 1)
        chart.legend().setAlignment(Qt.AlignBottom)
        charts.style_chart(chart)
        self.fleet_chart.setChart(chart)
