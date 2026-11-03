"""Findings: a filter bar (search, filter chips, quick toggles), the findings table, and a detail pane."""

import numpy as np
import pandas as pd
from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QDoubleSpinBox, QFileDialog, QFrame, QHBoxLayout, QMessageBox, QSizePolicy, QVBoxLayout,
    QWidget,
)

from tenable_net import reports
from tenable_net.gui import theme
from tenable_net.gui.filters import filter_mask, search_index
from tenable_net.gui.models import DataFrameModel, MaskFilterProxy
from tenable_net.gui.widgets import (
    FilterChip, FindingDetail, IconButton, SearchField, Splitter, ToggleChip, button, divider, fit_columns, label,
    make_table, severity_icon,
)
from tenable_net.normalize import SEVERITY_ORDER

FINDING_TABLE_COLUMNS = [
    "risk", "severity", "plugin_name", "hostname", "change", "vpr", "exploit_available", "cves", "ip", "vendor",
    "plugin_id", "port", "state", "days_open", "last_found",
]
STATES = ("OPEN", "REOPENED", "FIXED")


class FindingsPanel(Splitter):
    """A findings table with a detail pane beside it (horizontal) or under it (vertical).
    Reused by the Findings and Devices views."""

    def __init__(self, columns=FINDING_TABLE_COLUMNS, parent=None, orientation=Qt.Vertical):
        super().__init__(orientation, line=True, parent=parent)
        self.model = DataFrameModel(columns=columns)
        self._columns = columns
        self.proxy = MaskFilterProxy(self)
        self.proxy.setSourceModel(self.model)
        self.table = make_table(self.proxy)  # the last column takes any spare width
        self.detail = FindingDetail()
        self.fleet_counts = None  # {plugin_id: devices} to use instead of counting this panel's rows
        self.addWidget(self.table)
        self.addWidget(self.detail)
        if orientation == Qt.Horizontal:
            self.setStretchFactor(0, 1)
            self.setStretchFactor(1, 0)
            self.setSizes([780, 400])
        else:
            self.setStretchFactor(0, 3)
            self.setStretchFactor(1, 2)
        self.table.selectionModel().currentRowChanged.connect(self._on_row)

    def set_frame(self, df):
        self.model.set_frame(df, self._columns)
        self.proxy.set_mask(None)
        if self.model.column_index("risk") >= 0:  # highest risk first
            self.table.sortByColumn(self.model.column_index("risk"), Qt.DescendingOrder)
        else:
            self.table.sortByColumn(self.model.column_index("severity"), Qt.AscendingOrder)
        if self.fleet_counts is not None:
            self.detail.shared_counts = self.fleet_counts
        elif "plugin_id" in df and "hostname" in df and not df.empty:
            self.detail.shared_counts = df.groupby("plugin_id")["hostname"].nunique().to_dict()
        fit_columns(self.table, max_width=220, caps={"plugin_name": 380, "cves": 150, "hostname": 200,
                                                     "vendor": 110})
        self.detail.clear_detail()
        if self.proxy.rowCount():
            self.table.selectRow(0)

    def set_mask(self, mask):
        self.proxy.set_mask(mask)
        if self.proxy.rowCount():
            self.table.selectRow(0)
        else:
            self.detail.clear_detail()

    def visible_frame(self):
        rows = [self.proxy.source_row(r) for r in range(self.proxy.rowCount())]
        return self.model.frame.iloc[rows]

    def _on_row(self, current, _previous):
        if not current.isValid():
            return
        row = self.proxy.mapToSource(current).row()
        self.detail.show_finding(self.model.frame.iloc[row])

    def refresh_theme(self):
        """Re-render the detail pane: its colours are baked into the rich text."""
        current = self.table.currentIndex()
        if current.isValid() and current.row() < self.proxy.rowCount():
            self._on_row(current, None)
        else:
            self.detail.clear_detail()


def _check_row(checkbox, count_label):
    row = QWidget()
    layout = QHBoxLayout(row)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(16)
    layout.addWidget(checkbox)
    layout.addStretch(1)
    layout.addWidget(count_label)
    return row


def summarize(names, total):
    """Chip text for a multi-select: None when everything (or nothing) is picked."""
    if len(names) in (0, total):
        return None
    return ", ".join(names) if len(names) <= 2 else f"{len(names)} selected"


class FindingsTab(QWidget):
    count_changed = Signal(int, int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.df = pd.DataFrame()
        self._counts = (0, 0, 0)
        self._debounce = QTimer(self, singleShot=True, interval=200)
        self._debounce.timeout.connect(self.apply_filters)

        # --- filter bar ----------------------------------------------------
        self.search = SearchField("Search device, IP, plugin, CVE…")
        self.search.setMinimumWidth(150)
        self.search.setMaximumWidth(300)
        self.search.textChanged.connect(self._debounce.start)

        self.severity_chip = FilterChip("Severity")
        self.sev_checks, self.sev_counts = {}, {}
        for sev in SEVERITY_ORDER:
            cb = QCheckBox(sev.title())
            cb.setChecked(True)
            cb.setIcon(severity_icon(sev))
            cb.toggled.connect(self.apply_filters)
            self.sev_checks[sev] = cb
            self.sev_counts[sev] = label("", "caption", "Muted")
            self.severity_chip.content_layout.addWidget(_check_row(cb, self.sev_counts[sev]))

        self.state_chip = FilterChip("State")
        self.state_checks = {}
        for state in STATES:
            cb = QCheckBox(state.title())
            cb.setChecked(True)
            cb.toggled.connect(self.apply_filters)
            self.state_checks[state] = cb
            self.state_chip.content_layout.addWidget(cb)

        self.vendor = QComboBox()
        self.vendor.setToolTip("Vendor")
        self.vendor.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.vendor.setMinimumContentsLength(9)
        self.vendor.currentIndexChanged.connect(self.apply_filters)

        self.vpr_chip = FilterChip("VPR")
        self.min_vpr = QDoubleSpinBox(minimum=0, maximum=10, singleStep=0.5, decimals=1)
        self.min_vpr.setSpecialValueText("Any")
        self.min_vpr.valueChanged.connect(self._debounce.start)
        vpr_row = QHBoxLayout()
        vpr_row.addWidget(label("Minimum VPR", "body"))
        vpr_row.addWidget(self.min_vpr)
        self.vpr_chip.content_layout.addLayout(vpr_row)
        self.vpr_chip.content_layout.addWidget(label("Tenable's 0–10 threat rating; 7+ is high.", "caption", "Muted"))

        self.exploitable = ToggleChip("Exploitable", "zap", "Only findings with a public exploit")
        self.exploitable.toggled.connect(self.apply_filters)
        self.changed = ToggleChip("New or reopened", "clock", "Only findings that are new or reopened since the "
                                                              "previous pull")
        self.changed.toggled.connect(self.apply_filters)

        self.count_label = label("", "body", "Muted")
        self.count_label.setTextFormat(Qt.RichText)
        self.count_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self.count_label.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)  # gives way on narrow windows
        self.reset_button = button("Clear", "ghost", tooltip="Clear every filter")
        self.reset_button.clicked.connect(self.reset_filters)
        export = IconButton("export", "Export the rows shown to CSV or Excel")
        export.clicked.connect(self.export_view)

        bar = QFrame()
        bar.setObjectName("Toolbar")
        row = QHBoxLayout(bar)
        row.setContentsMargins(14, 10, 10, 10)
        row.setSpacing(6)
        for w in (self.search, self.severity_chip, self.state_chip, self.vendor, self.vpr_chip, self.exploitable,
                  self.changed):
            row.addWidget(w)
        row.addWidget(self.count_label, 1)
        row.addSpacing(4)
        row.addWidget(self.reset_button)
        row.addWidget(export)

        # --- table + detail --------------------------------------------------
        self.panel = FindingsPanel(orientation=Qt.Horizontal)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(bar)
        layout.addWidget(divider())
        layout.addWidget(self.panel, 1)

    def set_data(self, findings):
        self.df = findings
        self.vendor.blockSignals(True)
        self.vendor.clear()
        self.vendor.addItem("All vendors", "")
        for vendor, n in findings["vendor"].value_counts().items():
            self.vendor.addItem(f"{vendor}  ·  {n:,}", vendor)
        self.vendor.blockSignals(False)
        counts = findings["severity"].astype(str).value_counts()
        for sev in self.sev_checks:
            self.sev_counts[sev].setText(f"{counts.get(sev, 0):,}")
        self.panel.set_frame(findings)
        search_index(self.panel.model.frame)  # build the search index now, not on the first keystroke
        self.apply_filters()

    def current_filters(self):
        return dict(
            severities=[s for s, cb in self.sev_checks.items() if cb.isChecked()],
            states=[s for s, cb in self.state_checks.items() if cb.isChecked()],
            vendor=self.vendor.currentData() or None,
            min_vpr=self.min_vpr.value(),
            exploitable_only=self.exploitable.isChecked(),
            text=self.search.text(),
            changed_only=self.changed.isChecked(),
        )

    def _update_chips(self, filters):
        sevs = [s.title() for s in filters["severities"]]
        self.severity_chip.set_summary(summarize(sevs, len(self.sev_checks)))
        states = [s.title() for s in filters["states"]]
        self.state_chip.set_summary(summarize(states, len(self.state_checks)))
        self.vpr_chip.set_summary(f"≥ {filters['min_vpr']:g}" if filters["min_vpr"] else None)
        active = bool(filters["vendor"])
        if bool(self.vendor.property("active")) != active:
            self.vendor.setProperty("active", active)
            theme.repolish(self.vendor)
        filtered = any((summarize(sevs, len(self.sev_checks)), summarize(states, len(self.state_checks)),
                        filters["vendor"], filters["min_vpr"], filters["exploitable_only"], filters["changed_only"],
                        filters["text"].strip()))
        self.reset_button.setVisible(filtered)

    def apply_filters(self):
        filters = self.current_filters()
        if self.df.empty:
            mask = np.zeros(0, dtype=bool)
        else:
            mask = filter_mask(self.panel.model.frame, **filters)
        self.panel.set_mask(mask)
        shown, total = int(mask.sum()), len(mask)
        devices = self.panel.model.frame.loc[mask, "hostname"].nunique() if total else 0
        self._counts = (shown, total, devices)
        self._render_count()
        self._update_chips(filters)
        self.count_changed.emit(shown, total)

    def _render_count(self):
        shown, total, devices = self._counts
        t = theme.tokens()
        lead = f"{shown:,}" if shown == total else f"{shown:,} of {total:,}"
        self.count_label.setText(f"<span style='color:{t['text']}'>{lead}</span> findings · "
                                 f"<span style='color:{t['text']}'>{devices:,}</span> devices")

    def refresh_theme(self):
        if not self.df.empty:
            self._render_count()
            self.panel.refresh_theme()

    def reset_filters(self):
        widgets = (*self.sev_checks.values(), *self.state_checks.values(), self.exploitable, self.changed,
                   self.vendor, self.min_vpr, self.search)
        for w in widgets:
            w.blockSignals(True)
        for cb in (*self.sev_checks.values(), *self.state_checks.values()):
            cb.setChecked(True)
        self.exploitable.setChecked(False)
        self.changed.setChecked(False)
        self.vendor.setCurrentIndex(0)
        self.min_vpr.setValue(0)
        self.search.clear()
        for w in widgets:
            w.blockSignals(False)
        self.exploitable.retheme()
        self.changed.retheme()
        self.apply_filters()

    def show_query(self, text, **filters):
        """Reset filters and apply a search (used for drill-down from the Overview)."""
        self.reset_filters()
        if filters.get("severity"):
            for sev, cb in self.sev_checks.items():
                cb.setChecked(sev == filters["severity"])
        if filters.get("exploitable"):
            self.exploitable.setChecked(True)
        if filters.get("changed"):
            self.changed.setChecked(True)
        self.search.setText(text)
        self.apply_filters()

    def export_view(self):
        frame = self.panel.visible_frame()
        if frame.empty:
            QMessageBox.information(self, "Export", "No findings in the current view.")
            return
        path, chosen = QFileDialog.getSaveFileName(
            self, "Export findings", "findings.xlsx", "Excel (*.xlsx);;CSV (*.csv)"
        )
        if not path:
            return
        frame = frame.drop(columns=["output"], errors="ignore")
        if path.lower().endswith(".csv") or "CSV" in chosen and not path.lower().endswith(".xlsx"):
            frame.to_csv(path if path.lower().endswith(".csv") else path + ".csv", index=False)
        else:
            reports.excel_safe(frame).to_excel(path, index=False, sheet_name="Findings")
        QMessageBox.information(self, "Export", f"Saved {len(frame):,} findings to\n{path}")

