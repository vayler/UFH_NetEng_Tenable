"""Overview: risk headline, KPI cards, highest-risk devices and vulnerabilities, distribution charts.

Laid out to read top-down in a meeting: how risky is the fleet, what's driving it, where it is.
Every number and row is clickable and jumps to the matching filtered view.
"""

import html

import pandas as pd
from PySide6.QtCharts import (
    QBarCategoryAxis, QBarSeries, QBarSet, QChart, QChartView, QHorizontalStackedBarSeries, QValueAxis,
)
from PySide6.QtCore import QMargins, QRectF, Qt, Signal
from PySide6.QtGui import QColor, QPainter
from PySide6.QtWidgets import (
    QFrame, QGridLayout, QGroupBox, QHBoxLayout, QLabel, QScrollArea, QSizePolicy, QVBoxLayout, QWidget,
)

from tenable_net import reports, risk
from tenable_net.gui import theme
from tenable_net.gui.models import RAW_ROLE, DataFrameModel
from tenable_net.gui.widgets import SEVERITY_COLORS, KpiCard, fit_columns, make_table, severity_color
from tenable_net.inventory import device_summary

CHART_SEVERITIES = ["critical", "high", "medium", "low"]
BAND_ORDER = ["Critical", "High", "Elevated", "Low"]


def _style_chart(chart, widget=None):
    """Quiet chart styling from the theme: no backgrounds, muted labels, faint gridlines."""
    t = theme.tokens()
    chart.setBackgroundVisible(False)
    chart.setPlotAreaBackgroundVisible(False)
    chart.setMargins(QMargins(0, 4, 0, 0))
    chart.legend().setLabelColor(QColor(t["text_muted"]))
    chart.legend().setFont(theme.font("caption"))
    chart.legend().setMarkerShape(chart.legend().MarkerShape.MarkerShapeCircle)
    chart.setAnimationOptions(QChart.SeriesAnimations)
    for axis in chart.axes():
        axis.setLabelsColor(QColor(t["text_muted"]))
        axis.setLabelsFont(theme.font("caption"))
        axis.setGridLineColor(QColor(t["border"]))
        axis.setLinePenColor(QColor(t["border_strong"]))


class BandBar(QWidget):
    """Horizontal bar split by risk band (device counts), with a legend underneath."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.counts = {}
        self.setMinimumHeight(44)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

    def set_counts(self, counts):
        self.counts = counts
        total = sum(counts.values()) or 1
        self.setToolTip(" · ".join(f"{b}: {counts.get(b, 0)} ({counts.get(b, 0) / total:.0%})" for b in BAND_ORDER))
        self.update()

    def paintEvent(self, _event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        t = theme.tokens()
        total = sum(self.counts.values())
        bar = QRectF(0, 2, self.width(), 10)
        p.setPen(Qt.NoPen)
        p.setBrush(QColor(t["border"]))
        p.drawRoundedRect(bar, 5, 5)
        x = 0.0
        for b in BAND_ORDER:
            n = self.counts.get(b, 0)
            if not n or not total:
                continue
            w = bar.width() * n / total
            p.setBrush(QColor(theme.band_color(b)))
            p.drawRect(QRectF(x, bar.top(), max(w - 2, 1), bar.height()))
            x += w
        p.setFont(theme.font("caption"))
        x = 0.0
        for b in BAND_ORDER:
            p.setPen(QColor(theme.band_color(b)))
            p.drawText(QRectF(x, 18, 14, 22), Qt.AlignVCenter, "●")
            p.setPen(QColor(t["text_muted"]))
            p.drawText(QRectF(x + 14, 18, 140, 22), Qt.AlignVCenter, f"{b}  {self.counts.get(b, 0)}")
            x += 120
        p.end()


def _section(title, widget, subtitle=None):
    box = QGroupBox(title)
    layout = QVBoxLayout(box)
    layout.setContentsMargins(4, 4, 4, 4)
    if subtitle:
        note = QLabel(subtitle)
        note.setObjectName("Muted")
        layout.addWidget(note)
    layout.addWidget(widget)
    return box


class OverviewTab(QWidget):
    device_activated = Signal(str)            # hostname
    plugin_activated = Signal(str)            # plugin id
    severity_activated = Signal(str)          # severity
    view_requested = Signal(str, dict)        # view name, navigate() filters
    action_activated = Signal(str)            # remediation action id

    def __init__(self, parent=None):
        super().__init__(parent)
        content = QWidget()
        self.grid = QVBoxLayout(content)
        self.grid.setContentsMargins(0, 0, 8, 0)
        self.grid.setSpacing(14)

        # 1. risk headline
        headline = QFrame()
        headline.setObjectName("Card")
        hl = QHBoxLayout(headline)
        hl.setContentsMargins(20, 16, 20, 16)
        hl.setSpacing(28)
        left = QVBoxLayout()
        cap = QLabel("FLEET RISK")
        cap.setObjectName("CardCaption")
        theme.set_font(cap, "caption", bold=True)
        cap.setToolTip("<b>Fleet risk</b><br>The average risk score (0-100) of the riskiest quarter of devices. "
                       "Device scores combine the worst finding, the rest of its findings and hardware status.")
        self.fleet_value = QLabel("–")
        theme.set_font(self.fleet_value, "kpi", bold=True)
        self.fleet_band = QLabel()
        left.addWidget(cap)
        left.addWidget(self.fleet_value)
        left.addWidget(self.fleet_band)
        left.addStretch(1)
        hl.addLayout(left)
        middle = QVBoxLayout()
        self.band_caption = QLabel()
        self.band_caption.setObjectName("CardCaption")
        theme.set_font(self.band_caption, "caption", bold=True)
        self.band_bar = BandBar()
        self.driver = QLabel()
        self.driver.setWordWrap(True)
        self.driver.setTextFormat(Qt.RichText)
        self.driver.linkActivated.connect(self._driver_clicked)
        middle.addWidget(self.band_caption)
        middle.addWidget(self.band_bar)
        middle.addWidget(self.driver)
        middle.addStretch(1)
        hl.addLayout(middle, 1)
        self.grid.addWidget(headline)

        # 2. KPI cards
        self.cards = {
            "critical": KpiCard("Critical findings", SEVERITY_COLORS["critical"], term="Severity"),
            "high": KpiCard("High findings", SEVERITY_COLORS["high"], term="Severity"),
            "exploitable": KpiCard("Exploit available", term="Exploit available"),
            "at_risk": KpiCard("Devices at Critical/High risk", term="Risk band"),
            "uncovered": KpiCard("Not under contract", term="Contract"),
            "upgrade": KpiCard("Software upgrade suggested", term="Software status"),
        }
        cards_row = QHBoxLayout()
        cards_row.setSpacing(12)
        for card in self.cards.values():
            cards_row.addWidget(card)
        self.cards["critical"].clicked.connect(lambda: self.severity_activated.emit("critical"))
        self.cards["high"].clicked.connect(lambda: self.severity_activated.emit("high"))
        self.cards["exploitable"].clicked.connect(lambda: self.view_requested.emit("findings", {"exploitable": True}))
        self.cards["at_risk"].clicked.connect(lambda: self.view_requested.emit("devices", {}))
        self.cards["uncovered"].clicked.connect(
            lambda: self.view_requested.emit("hardware", {"filter": "Not under contract"}))
        self.cards["upgrade"].clicked.connect(
            lambda: self.view_requested.emit("hardware", {"filter": "Software upgrade suggested"}))
        self.grid.addLayout(cards_row)

        # 2b. what changed since the last pull
        changes = QFrame()
        changes.setObjectName("Card")
        cl = QHBoxLayout(changes)
        cl.setContentsMargins(20, 14, 20, 14)
        cl.setSpacing(28)
        stats = QVBoxLayout()
        self.changes_title = QLabel("SINCE LAST PULL")
        self.changes_title.setObjectName("CardCaption")
        theme.set_font(self.changes_title, "caption", bold=True)
        stats.addWidget(self.changes_title)
        self.change_stats = {}
        row = QHBoxLayout()
        row.setSpacing(26)
        for key, label in (("new", "New"), ("fixed", "Fixed"), ("reopened", "Reopened")):
            block = QVBoxLayout()
            value = QLabel("–")
            theme.set_font(value, "title", bold=True)
            caption = QLabel(label)
            caption.setObjectName("Muted")
            block.addWidget(value)
            block.addWidget(caption)
            row.addLayout(block)
            self.change_stats[key] = (value, caption)
        row.addStretch(1)
        stats.addLayout(row)
        self.changes_note = QLabel()
        self.changes_note.setObjectName("Muted")
        self.changes_note.setWordWrap(True)
        self.changes_note.setTextFormat(Qt.RichText)
        self.changes_note.linkActivated.connect(lambda _l: self.view_requested.emit("findings", {"changed": True}))
        stats.addWidget(self.changes_note)
        stats.addStretch(1)
        cl.addLayout(stats)
        self.new_model = DataFrameModel()
        self.new_view = make_table(self.new_model, stretch_column="plugin_name")
        self.new_view.setSortingEnabled(False)
        self.new_view.setMaximumHeight(190)
        self.new_view.clicked.connect(self._new_clicked)
        cl.addWidget(self.new_view, 1)
        self.grid.addWidget(changes)

        # 2c. top remediation actions
        self.actions_model = DataFrameModel()
        self.actions_view = make_table(self.actions_model, stretch_column="title")
        self.actions_view.setSortingEnabled(False)
        self.actions_view.setMinimumHeight(200)
        self.actions_view.clicked.connect(self._action_clicked)
        self.grid.addWidget(_section("Top actions", self.actions_view,
                                     "The fixes that remove the most risk for the least work. Click one for the "
                                     "devices involved."))

        # 3. highest-risk devices / vulnerabilities
        self.devices_model = DataFrameModel()
        self.devices_view = make_table(self.devices_model, stretch_column="top_finding")
        self.devices_view.setSortingEnabled(False)
        self.devices_view.clicked.connect(self._device_clicked)
        self.devices_view.setMinimumHeight(330)
        self.plugins_model = DataFrameModel()
        self.plugins_view = make_table(self.plugins_model, stretch_column="plugin_name")
        self.plugins_view.setSortingEnabled(False)
        self.plugins_view.clicked.connect(self._plugin_clicked)
        self.plugins_view.setMinimumHeight(330)
        tables = QGridLayout()
        tables.setSpacing(14)
        tables.addWidget(_section("Highest-risk devices", self.devices_view, "Click a device to open it."), 0, 0)
        tables.addWidget(_section("Highest-risk vulnerabilities", self.plugins_view,
                                  "Severe and widespread first. Click to list affected devices."), 0, 1)
        self.grid.addLayout(tables)

        # 4. distribution charts
        self.sev_chart = QChartView()
        self.vendor_chart = QChartView()
        for view in (self.sev_chart, self.vendor_chart):
            view.setRenderHint(QPainter.Antialiasing)
            view.setMinimumHeight(250)
            view.setStyleSheet("background: transparent; border: none;")
        charts = QGridLayout()
        charts.setSpacing(14)
        charts.addWidget(_section("Findings by severity", self.sev_chart, "Click a bar to list those findings."), 0, 0)
        charts.addWidget(_section("Severity by vendor", self.vendor_chart), 0, 1)
        self.grid.addLayout(charts)
        self.grid.addStretch(1)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setWidget(content)
        content.setObjectName("OverviewContent")
        scroll.setStyleSheet("QScrollArea { background: transparent; } #OverviewContent { background: transparent; }")
        scroll.viewport().setAutoFillBackground(False)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)
        self.device_risk = pd.DataFrame()
        self.top_plugin_id = None

    # ---- data -----------------------------------------------------------------------------
    def set_data(self, findings, inventory=None):
        scored = findings if "risk" in findings else risk.add_finding_scores(findings)
        hw = device_summary(inventory) if inventory is not None and not inventory.empty else None
        self.device_risk = risk.device_scores(scored, hw)
        summary = risk.fleet_summary(self.device_risk)
        counts = summary["counts"]

        self.fleet_value.setText(f"{summary['index']:.0f}")
        self.fleet_band.setText(theme.band_badge(summary["band"], f"{summary['band']} risk"))
        self.fleet_band.setProperty("band", summary["band"])
        self.band_caption.setText(f"{summary['devices']:,} DEVICES BY RISK BAND")
        self.band_bar.set_counts(counts)
        self._set_driver(scored)

        sev = scored["severity"].astype(str)
        self.cards["critical"].set_value(int((sev == "critical").sum()))
        self.cards["high"].set_value(int((sev == "high").sum()))
        self.cards["exploitable"].set_value(int((scored["exploit_available"] == True).sum()))  # noqa: E712
        self.cards["at_risk"].set_value(counts["Critical"] + counts["High"])
        if hw is not None and not hw.empty:
            self.cards["uncovered"].set_value(int((hw["contract"] == "Not covered").sum()))
            self.cards["upgrade"].set_value(int((hw["sw_status"] == "Upgrade suggested").sum()))
        else:
            for key in ("uncovered", "upgrade"):
                self.cards[key].set_value("–")
                self.cards[key].delta.setText("Needs hardware inventory")

        counts_by_device = (reports.by_device(scored)[["hostname", "critical", "high"]] if not scored.empty
                            else pd.DataFrame(columns=["hostname", "critical", "high"]))
        top_devices = self.device_risk.head(12).merge(counts_by_device, on="hostname", how="left")
        self.devices_model.set_frame(top_devices, ["hostname", "risk", "critical", "high", "top_finding"])
        fit_columns(self.devices_view, max_width=220)

        plugins = self._top_plugins(scored)
        self.plugins_model.set_frame(plugins, ["risk", "severity", "devices", "plugin_id", "plugin_name"])
        fit_columns(self.plugins_view, max_width=220)

        self._severity_chart(scored)
        self._vendor_chart(scored)

    @staticmethod
    def _top_plugins(scored):
        cols = ["risk", "severity", "devices", "plugin_id", "plugin_name"]
        if scored.empty or "risk" not in scored:
            return pd.DataFrame(columns=cols)
        g = scored[scored["risk"] > 0].groupby(["plugin_id", "plugin_name"], observed=True).agg(
            risk=("risk", "max"), severity=("severity", "min"), devices=("hostname", "nunique")).reset_index()
        g["impact"] = g["risk"] * (1 + g["devices"].clip(upper=50) / 10)  # severe and widespread first
        return g.sort_values(["impact", "risk"], ascending=False).head(12).reset_index(drop=True)

    def _set_driver(self, scored):
        top = self._top_plugins(scored)
        if top.empty:
            self.driver.setText("<span style='color:gray'>No scored findings.</span>")
            return
        row = top.iloc[0]
        self.top_plugin_id = str(row["plugin_id"])
        t = theme.tokens()
        n = int(row["devices"])
        self.driver.setText(
            f"<span style='color:{t['text_muted']}'>Fix first:</span> "
            f"<a href='plugin' style='color:{t['link']}; text-decoration:none'>"
            f"<b>{html.escape(str(row['plugin_name']))}</b></a>"
            f" &nbsp;{theme.severity_badge(str(row['severity']))}&nbsp; on <b>{n}</b> device{'s' if n != 1 else ''}"
            f" &nbsp;<span style='color:{t['text_muted']}'>(risk {row['risk']:.0f})</span>")

    def _driver_clicked(self, _link):
        if self.top_plugin_id:
            self.plugin_activated.emit(self.top_plugin_id)

    # ---- history ---------------------------------------------------------------------------
    def set_history(self, changes, series):
        """Deltas and sparklines on the KPI cards, and the 'since last pull' panel."""
        recent = series.tail(20) if series is not None and not series.empty else None
        trend_cols = {"critical": "critical", "high": "high", "exploitable": "exploitable", "at_risk": "at_risk"}
        for card_key, col in trend_cols.items():
            self.cards[card_key].set_trend(recent[col].tolist() if recent is not None else [])
            delta = changes["deltas"] if changes else None
            if delta is None:
                self.cards[card_key].set_delta(None)
            elif card_key == "at_risk":
                self.cards[card_key].set_delta(delta["Critical"] + delta["High"])
            else:
                self.cards[card_key].set_delta(delta[col])
        if changes:
            d = changes["deltas"]["fleet"]
            arrow = "▲" if d > 0 else ("▼" if d < 0 else "")
            color = theme.tokens()["bad" if d > 0 else "good"]
            change = (f"&nbsp; <span style='color:{color}; font-weight:600'>{arrow} {abs(d):g}</span>"
                      f"<span style='color:{theme.tokens()['text_muted']}'> since last pull</span>" if d else "")
            band_name = self.fleet_band.property("band") or ""
            self.fleet_band.setText(theme.band_badge(band_name, f"{band_name} risk") + change)
            prev = pd.Timestamp(changes["previous_at"])
            when = (prev.tz_convert(None) if prev.tzinfo else prev).strftime("%d %b %H:%M")
            self.changes_title.setText(f"SINCE LAST PULL  ·  {when}")
            new, fixed, reopened = changes["new"], changes["fixed"], changes["reopened"]
            t = theme.tokens()
            for key, frame, token in (("new", new, "bad"), ("fixed", fixed, "good"), ("reopened", reopened, "warn")):
                value, _cap = self.change_stats[key]
                value.setText(f"{len(frame):,}")
                value.setStyleSheet(f"color: {t[token]};" if len(frame) else "")
            crit_new = int((pd.concat([new, reopened])["severity"].isin(["critical", "high"])).sum())
            link = f"<a href='changed' style='color:{t['link']}'>Show new and reopened findings →</a>"
            if len(new) + len(reopened):
                self.changes_note.setText(f"{crit_new} of them are critical or high. {link}")
            else:
                self.changes_note.setText("Nothing new or reopened since the last pull.")
            top_new = pd.concat([reopened, new]).sort_values("risk", ascending=False).head(6)
            self.new_model.set_frame(top_new, ["risk", "severity", "hostname", "plugin_name"])
            fit_columns(self.new_view, max_width=200)
            self.new_view.setVisible(not top_new.empty)
        else:
            for value, _cap in self.change_stats.values():
                value.setText("–")
            self.changes_title.setText("SINCE LAST PULL")
            self.changes_note.setText("History starts with this pull. After your next pull this shows which "
                                      "findings are new, fixed or reopened, and the cards show the change.")
            self.new_view.setVisible(False)

    def set_actions(self, actions):
        top = actions.head(5) if actions is not None else pd.DataFrame()
        self.actions_model.set_frame(top, ["rank", "type", "title", "confidence", "devices", "critical", "high"])
        fit_columns(self.actions_view, max_width=160)

    def _action_clicked(self, index):
        frame = self.actions_model.frame
        if index.isValid() and index.row() < len(frame):
            self.action_activated.emit(str(frame.iloc[index.row()]["id"]))

    def _new_clicked(self, index):
        frame = self.new_model.frame
        if index.isValid() and index.row() < len(frame):
            self.device_activated.emit(str(frame.iloc[index.row()]["hostname"]))

    # ---- charts -----------------------------------------------------------------------------
    def _severity_chart(self, findings):
        counts = findings["severity"].astype(str).value_counts()
        series = QBarSeries()
        series.setBarWidth(0.7)
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
        _style_chart(chart)
        for bar in series.barSets():
            bar.setLabelColor(QColor(theme.tokens()["text_muted"]))
        self.sev_chart.setChart(chart)

    def _vendor_chart(self, findings):
        vendors = reports.by_vendor_os(findings) if not findings.empty else pd.DataFrame()
        chart = QChart()
        if not vendors.empty:
            by_vendor = vendors.groupby("vendor")[[c for c in CHART_SEVERITIES if c in vendors]].sum()
            by_vendor = by_vendor.loc[by_vendor.sum(axis=1).sort_values().index].tail(8)
            series = QHorizontalStackedBarSeries()
            series.setBarWidth(0.6)
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
        _style_chart(chart)
        self.vendor_chart.setChart(chart)

    # ---- clicks -----------------------------------------------------------------------------
    def _device_clicked(self, index):
        frame = self.devices_model.frame
        if index.isValid() and index.row() < len(frame):
            self.device_activated.emit(str(frame.iloc[index.row()]["hostname"]))

    def _plugin_clicked(self, index):
        if index.isValid():
            pid = self.plugins_model.index(index.row(), self.plugins_model.column_index("plugin_id")).data(RAW_ROLE)
            self.plugin_activated.emit(str(pid))
