"""Overview: risk headline, key numbers, what changed, top actions, riskiest devices and vulnerabilities, charts.

Laid out to read top-down in a meeting: how risky is the fleet, what's driving it, where it is.
Every number and row is clickable and jumps to the matching filtered view.
"""

import html

import pandas as pd
from PySide6.QtCharts import QBarCategoryAxis, QBarSeries, QBarSet, QChart, QHorizontalStackedBarSeries, QValueAxis
from PySide6.QtCore import QRectF, Qt, Signal
from PySide6.QtGui import QColor, QPainter
from PySide6.QtWidgets import (
    QAbstractItemView, QFrame, QGridLayout, QHBoxLayout, QLabel, QScrollArea, QSizePolicy, QVBoxLayout, QWidget,
)

from tenable_net import reports, risk
from tenable_net.gui import charts, theme
from tenable_net.gui.models import DataFrameModel
from tenable_net.gui.widgets import (
    SEVERITY_COLORS, KpiCard, Panel, StatStrip, button, fit_columns, label, make_table,
)
from tenable_net.inventory import device_summary

CHART_SEVERITIES = ["critical", "high", "medium", "low"]
BAND_ORDER = ["Critical", "High", "Elevated", "Low"]
TOP_ROWS = 8


class BandBar(QWidget):
    """Thin bar split by risk band (device counts), with a legend underneath."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.counts = {}
        self.setMinimumHeight(46)
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
        bar = QRectF(0, 4, self.width(), 8)
        p.setPen(Qt.NoPen)
        p.setBrush(QColor(t["border"]))
        p.drawRoundedRect(bar, 4, 4)
        x = 0.0
        shown = [b for b in BAND_ORDER if self.counts.get(b, 0)]
        for i, b in enumerate(shown):
            w = bar.width() * self.counts[b] / total
            gap = 3 if i < len(shown) - 1 else 0
            p.setBrush(QColor(theme.band_color(b)))
            p.drawRoundedRect(QRectF(x, bar.top(), max(w - gap, 2), bar.height()), 3, 3)
            x += w
        caption = theme.font("caption")
        p.setFont(caption)
        fm = p.fontMetrics()
        x = 0.0
        for b in BAND_ORDER:
            p.setPen(Qt.NoPen)
            p.setBrush(QColor(theme.band_color(b)))
            p.drawEllipse(QRectF(x, 28 + fm.height() / 2 - 3.5, 7, 7))
            p.setPen(QColor(t["text_muted"]))
            p.drawText(QRectF(x + 12, 24, 200, fm.height() + 8), Qt.AlignVCenter, b)
            n = f"{self.counts.get(b, 0):,}"
            lw = fm.horizontalAdvance(b) + 6
            p.setPen(QColor(t["text"]))
            p.drawText(QRectF(x + 12 + lw, 24, 80, fm.height() + 8), Qt.AlignVCenter, n)
            x += 12 + lw + fm.horizontalAdvance(n) + 22
        p.end()


def compact_table(model, stretch_column, rows=TOP_ROWS):
    """A clickable table sized to show `rows` rows without scrolling (dashboard style)."""
    view = make_table(model, stretch_column=stretch_column)
    view.setSortingEnabled(False)
    view.setSelectionMode(QAbstractItemView.NoSelection)
    view.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
    # no horizontal scrollbar either: it would cover the last row; the stretch column absorbs the width
    view.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
    view.viewport().setCursor(Qt.PointingHandCursor)
    view._rows = rows
    _fit_height(view)
    return view


def _fit_height(view, n=None):
    """Exactly n rows plus the header. Call after the model has columns: an empty header reports no height."""
    n = view._rows if n is None else n
    header = view.horizontalHeader()
    header_height = max(header.sizeHint().height(), header.minimumHeight())
    view.setFixedHeight(header_height + n * theme.row_height() + 2 * view.frameWidth() + 1)


class OverviewTab(QWidget):
    device_activated = Signal(str)            # hostname
    plugin_activated = Signal(str)            # plugin id
    severity_activated = Signal(str)          # severity
    view_requested = Signal(str, dict)        # view name, navigate() filters
    action_activated = Signal(str)            # remediation action id

    def __init__(self, parent=None):
        super().__init__(parent)
        content = QWidget()
        content.setObjectName("ScrollContent")
        self.grid = QVBoxLayout(content)
        self.grid.setContentsMargins(20, 18, 20, 20)
        self.grid.setSpacing(14)

        # 1. risk headline
        headline = QFrame()
        headline.setObjectName("Panel")
        hl = QHBoxLayout(headline)
        hl.setContentsMargins(20, 16, 20, 16)
        hl.setSpacing(32)
        left = QVBoxLayout()
        left.setSpacing(2)
        cap = label("Fleet risk", "caption", "StatCaption", weight="medium")
        cap.setToolTip("<b>Fleet risk</b><br>The average risk score (0-100) of the riskiest quarter of devices. "
                       "Device scores combine the worst finding, the rest of its findings and hardware status.")
        self.fleet_value = label("–", "display")
        self.fleet_band = label("", "body")
        self.fleet_band.setTextFormat(Qt.RichText)
        left.addWidget(cap)
        left.addWidget(self.fleet_value)
        left.addWidget(self.fleet_band)
        left.addStretch(1)
        hl.addLayout(left)
        hl.addWidget(_vline())
        middle = QVBoxLayout()
        middle.setSpacing(8)
        self.band_caption = label("", "caption", "StatCaption", weight="medium")
        self.band_bar = BandBar()
        self.driver = QLabel()
        self.driver.setWordWrap(True)
        self.driver.setTextFormat(Qt.RichText)
        self.driver.linkActivated.connect(self._driver_clicked)
        self.driver.setCursor(Qt.PointingHandCursor)
        middle.addWidget(self.band_caption)
        middle.addWidget(self.band_bar)
        middle.addSpacing(2)
        middle.addWidget(self.driver)
        middle.addStretch(1)
        hl.addLayout(middle, 1)
        self.grid.addWidget(headline)
        self._driver = None

        # 2. key numbers
        self.cards = {
            "critical": KpiCard("Critical findings", SEVERITY_COLORS["critical"], term="Severity"),
            "high": KpiCard("High findings", SEVERITY_COLORS["high"], term="Severity"),
            "exploitable": KpiCard("Exploit available", term="Exploit available"),
            "at_risk": KpiCard("Devices at risk", term="Risk band"),
            "uncovered": KpiCard("Not under contract", term="Contract"),
            "upgrade": KpiCard("Upgrade suggested", term="Software status"),
        }
        self.cards["at_risk"].setToolTip("<b>Devices at risk</b><br>Devices whose risk score puts them in the Critical "
                                         "or High band (50 or more). Click to see devices ranked by risk.")
        self.cards["critical"].clicked.connect(lambda: self.severity_activated.emit("critical"))
        self.cards["high"].clicked.connect(lambda: self.severity_activated.emit("high"))
        self.cards["exploitable"].clicked.connect(lambda: self.view_requested.emit("findings", {"exploitable": True}))
        self.cards["at_risk"].clicked.connect(lambda: self.view_requested.emit("devices", {"reset": True}))
        self.cards["uncovered"].clicked.connect(
            lambda: self.view_requested.emit("hardware", {"filter": "Not under contract"}))
        self.cards["upgrade"].clicked.connect(
            lambda: self.view_requested.emit("hardware", {"filter": "Software upgrade suggested"}))
        self.grid.addWidget(StatStrip(list(self.cards.values())))

        # 3. what changed since the last pull
        changes = Panel("Since last pull")
        self.changes_panel = changes
        self.changes_title = changes.subtitle
        self.changes_link = changes.add_action(button("Show new and reopened", "link"))
        self.changes_link.clicked.connect(lambda: self.view_requested.emit("findings", {"changed": True}))
        row = QHBoxLayout()
        row.setSpacing(24)
        stats = QVBoxLayout()
        stats.setSpacing(10)
        self.change_stats = {}
        numbers = QHBoxLayout()
        numbers.setSpacing(24)
        for key, text, token in (("new", "New", "dot_bad"), ("fixed", "Fixed", "dot_good"),
                                 ("reopened", "Reopened", "dot_warn")):
            block = QVBoxLayout()
            block.setSpacing(0)
            value = label("–", "kpi")
            caption = label("", "caption", "Muted")
            caption.setTextFormat(Qt.RichText)
            caption.setProperty("dot_token", token)
            caption.setProperty("text_", text)
            block.addWidget(value)
            block.addWidget(caption)
            numbers.addLayout(block)
            self.change_stats[key] = (value, caption)
        numbers.addStretch(1)
        stats.addLayout(numbers)
        self.changes_note = label("", "body", "Muted", wrap=True)
        self.changes_note.setTextFormat(Qt.RichText)
        self.changes_note.linkActivated.connect(lambda _l: self.view_requested.emit("findings", {"changed": True}))
        stats.addWidget(self.changes_note)
        stats.addStretch(1)
        stats_box = QWidget()
        stats_box.setLayout(stats)
        stats_box.setFixedWidth(300)
        row.addWidget(stats_box)
        self.new_model = DataFrameModel()
        self.new_view = compact_table(self.new_model, "plugin_name", rows=5)
        self.new_view.clicked.connect(self._new_clicked)
        row.addWidget(self.new_view, 1)
        changes.body.setContentsMargins(16, 4, 6, 8)
        changes.body.addLayout(row)
        self.grid.addWidget(changes)

        # 4. top remediation actions
        self.actions_model = DataFrameModel()
        self.actions_view = compact_table(self.actions_model, "title", rows=5)
        self.actions_view.clicked.connect(self._action_clicked)
        actions_panel = Panel("Top actions", self.actions_view, "Fixes that remove the most risk for the least work",
                              flush=True)
        actions_panel.add_action(button("Open plan", "link")).clicked.connect(
            lambda: self.view_requested.emit("remediation", {"reset": True}))
        self.grid.addWidget(actions_panel)

        # 5. highest-risk devices / vulnerabilities
        self.devices_model = DataFrameModel()
        self.devices_view = compact_table(self.devices_model, "top_finding")
        self.devices_view.clicked.connect(self._device_clicked)
        self.plugins_model = DataFrameModel()
        self.plugins_view = compact_table(self.plugins_model, "plugin_name")
        self.plugins_view.clicked.connect(self._plugin_clicked)
        devices_panel = Panel("Highest-risk devices", self.devices_view, flush=True)
        devices_panel.add_action(button("All devices", "link")).clicked.connect(
            lambda: self.view_requested.emit("devices", {"reset": True}))
        plugins_panel = Panel("Highest-risk vulnerabilities", self.plugins_view, "Severe and widespread first",
                              flush=True)
        plugins_panel.add_action(button("All findings", "link")).clicked.connect(
            lambda: self.view_requested.emit("findings", {"text": ""}))  # an empty query clears the filters
        tables = QGridLayout()
        tables.setSpacing(14)
        tables.addWidget(devices_panel, 0, 0)
        tables.addWidget(plugins_panel, 0, 1)
        self.grid.addLayout(tables)

        # 6. distribution charts
        self.sev_chart = charts.chart_view(fixed_height=250)
        self.vendor_chart = charts.chart_view(fixed_height=250)
        chart_row = QGridLayout()
        chart_row.setSpacing(14)
        chart_row.addWidget(Panel("Findings by severity", self.sev_chart, "Click a bar to list those findings"), 0, 0)
        chart_row.addWidget(Panel("Severity by vendor", self.vendor_chart), 0, 1)
        self.grid.addLayout(chart_row)
        self.grid.addStretch(1)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setWidget(content)
        scroll.viewport().setAutoFillBackground(False)
        content.setAutoFillBackground(False)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)
        self.device_risk = pd.DataFrame()
        self.top_plugin_id = None
        self._render_change_captions()

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
        self.band_caption.setText(f"{summary['devices']:,} devices by risk band")
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
            for key in ("uncovered", "upgrade"):
                self.cards[key].set_delta(None)
        else:
            for key in ("uncovered", "upgrade"):
                self.cards[key].set_value("–")
                self.cards[key].delta.setText("Needs hardware inventory")

        counts_by_device = (reports.by_device(scored)[["hostname", "critical", "high"]] if not scored.empty
                            else pd.DataFrame(columns=["hostname", "critical", "high"]))
        top_devices = self.device_risk.head(TOP_ROWS).merge(counts_by_device, on="hostname", how="left")
        self.devices_model.set_frame(top_devices, ["hostname", "risk", "critical", "high", "top_finding"])
        fit_columns(self.devices_view, max_width=230)

        plugins = self._top_plugins(scored)
        self.plugins_model.set_frame(plugins, ["risk", "severity", "devices", "plugin_name"])
        fit_columns(self.plugins_view, max_width=230)
        rows = max(len(top_devices), len(plugins), 1)  # the two panels sit side by side: same height
        _fit_height(self.devices_view, rows)
        _fit_height(self.plugins_view, rows)

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
        return g.sort_values(["impact", "risk"], ascending=False).head(TOP_ROWS).reset_index(drop=True)

    def _set_driver(self, scored):
        top = self._top_plugins(scored)
        if top.empty:
            self._driver = None
            self.top_plugin_id = None
            self.driver.setText(f"<span style='color:{theme.tokens()['text_muted']}'>No scored findings.</span>")
            return
        row = top.iloc[0]
        self.top_plugin_id = str(row["plugin_id"])
        self._driver = (str(row["plugin_name"]), str(row["severity"]), int(row["devices"]), float(row["risk"]))
        self.driver.setText(self.driver_text())

    def driver_text(self, mode_name=None):
        """'Fix first: <plugin> …' as rich text (mode_name='light' for print)."""
        if self._driver is None:
            return ""
        name, sev, n, score = self._driver
        t = theme.tokens(mode_name)
        return (f"<span style='color:{t['text_muted']}'>Fix first</span>&nbsp;&nbsp;"
                f"<a href='plugin' style='color:{t['accent_text']}; text-decoration:none; font-weight:500'>"
                f"{html.escape(name)}</a>&nbsp;&nbsp;"
                f"<span style='color:{t['text_muted']}'>{theme.severity_badge(sev)} · on "
                f"<span style='color:{t['text']}'>{n}</span> device{'s' if n != 1 else ''} · risk {score:.0f}</span>")

    def _driver_clicked(self, _link):
        if self.top_plugin_id:
            self.plugin_activated.emit(self.top_plugin_id)

    # ---- history ---------------------------------------------------------------------------
    def _render_change_captions(self):
        t = theme.tokens()
        for _value, caption in self.change_stats.values():
            caption.setText(f"<span style='color:{t[caption.property('dot_token')]}'>●</span>&nbsp;"
                            f"{caption.property('text_')}")

    def set_history(self, changes, series):
        """Deltas and sparklines on the stat tiles, and the 'since last pull' panel."""
        self._render_change_captions()
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
        t = theme.tokens()
        if changes:
            d = changes["deltas"]["fleet"]
            arrow = "▲" if d > 0 else ("▼" if d < 0 else "")
            color = t["bad" if d > 0 else "good"]
            change = (f"&nbsp;&nbsp;<span style='color:{color}; font-weight:500'>{arrow} {abs(d):g}</span>"
                      f"<span style='color:{t['text_muted']}'> since last pull</span>" if d else "")
            band_name = self.fleet_band.property("band") or ""
            self.fleet_band.setText(theme.band_badge(band_name, f"{band_name} risk") + change)
            prev = pd.Timestamp(changes["previous_at"])
            when = (prev.tz_convert(None) if prev.tzinfo else prev).strftime("%d %b %H:%M")
            self.changes_panel.set_subtitle(f"compared with the pull on {when}")
            new, fixed, reopened = changes["new"], changes["fixed"], changes["reopened"]
            for key, frame in (("new", new), ("fixed", fixed), ("reopened", reopened)):
                value, _cap = self.change_stats[key]
                value.setText(f"{len(frame):,}")
            parts = [frame for frame in (reopened, new) if not frame.empty]  # (pandas 2 warns on empty parts)
            changed = pd.concat(parts) if parts else new
            crit_new = int(changed["severity"].isin(["critical", "high"]).sum())
            if len(new) + len(reopened):
                self.changes_note.setText(f"{crit_new} of the new and reopened findings are critical or high.")
            else:
                self.changes_note.setText("Nothing new or reopened since the last pull.")
            self.changes_link.setVisible(bool(len(new) + len(reopened)))
            top_new = changed.sort_values("risk", ascending=False).head(5)
            top_new = top_new.assign(change=["Reopened" if k in set(reopened["key"]) else "New" for k in top_new["key"]])
            self.new_model.set_frame(top_new, ["risk", "change", "severity", "hostname", "plugin_name"])
            fit_columns(self.new_view, max_width=200)
            self.new_view.setVisible(not top_new.empty)
            _fit_height(self.new_view, max(len(top_new), 1))
        else:
            for value, _cap in self.change_stats.values():
                value.setText("–")
            self.changes_panel.set_subtitle("")
            self.changes_link.setVisible(False)
            self.changes_note.setText("History starts with this pull. After your next pull this shows which "
                                      "findings are new, fixed or reopened, and the numbers above show the change.")
            self.new_view.setVisible(False)

    def set_actions(self, actions):
        top = actions.head(5) if actions is not None else pd.DataFrame()
        self.actions_model.set_frame(top, ["rank", "type", "title", "confidence", "devices", "critical", "high"])
        fit_columns(self.actions_view, max_width=160)
        _fit_height(self.actions_view, max(len(top), 1))

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
        series.setBarWidth(0.62)
        for sev in CHART_SEVERITIES:
            bar = QBarSet(sev.title())
            bar.append(int(counts.get(sev, 0)))
            charts.no_border(bar, SEVERITY_COLORS[sev])
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
        y.setRange(0, max([int(counts.get(s, 0)) for s in CHART_SEVERITIES] + [1]) * 1.18)
        y.setTickCount(5)
        chart.addAxis(x, Qt.AlignBottom)
        chart.addAxis(y, Qt.AlignLeft)
        series.attachAxis(x)
        series.attachAxis(y)
        chart.legend().setAlignment(Qt.AlignBottom)
        charts.style_chart(chart)
        self.sev_chart.setChart(chart)

    def _vendor_chart(self, findings):
        vendors = reports.by_vendor_os(findings) if not findings.empty else pd.DataFrame()
        chart = QChart()
        if not vendors.empty:
            by_vendor = vendors.groupby("vendor")[[c for c in CHART_SEVERITIES if c in vendors]].sum()
            by_vendor = by_vendor.loc[by_vendor.sum(axis=1).sort_values().index].tail(8)
            series = QHorizontalStackedBarSeries()
            series.setBarWidth(0.56)
            for sev in CHART_SEVERITIES:
                bar = QBarSet(sev.title())
                bar.append([int(v) for v in by_vendor.get(sev, pd.Series(0, index=by_vendor.index))])
                charts.no_border(bar, SEVERITY_COLORS[sev])
                series.append(bar)
            chart.addSeries(series)
            y = QBarCategoryAxis()
            y.append(list(by_vendor.index))
            y.setTruncateLabels(False)
            x = QValueAxis()
            x.setLabelFormat("%d")
            x.setTickCount(5)
            chart.addAxis(y, Qt.AlignLeft)
            chart.addAxis(x, Qt.AlignBottom)
            series.attachAxis(y)
            series.attachAxis(x)
        chart.legend().setAlignment(Qt.AlignBottom)
        charts.style_chart(chart)
        self.vendor_chart.setChart(chart)

    def refresh_theme(self):
        charts.restyle(self.sev_chart, self.vendor_chart)

    # ---- clicks -----------------------------------------------------------------------------
    def _device_clicked(self, index):
        frame = self.devices_model.frame
        if index.isValid() and index.row() < len(frame):
            self.device_activated.emit(str(frame.iloc[index.row()]["hostname"]))

    def _plugin_clicked(self, index):
        frame = self.plugins_model.frame
        if index.isValid() and index.row() < len(frame):
            self.plugin_activated.emit(str(frame.iloc[index.row()]["plugin_id"]))


def _vline():
    line = QFrame()
    line.setObjectName("Divider")
    line.setFixedWidth(1)
    return line

