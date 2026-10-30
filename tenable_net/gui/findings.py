"""Findings tab: filter sidebar, sortable table, detail pane, export of the filtered view."""

import numpy as np
import pandas as pd
from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QDoubleSpinBox, QFileDialog, QFormLayout, QGroupBox, QHBoxLayout, QLabel,
    QLineEdit, QMessageBox, QPushButton, QSplitter, QVBoxLayout, QWidget,
)

from tenable_net import reports
from tenable_net.gui.filters import filter_mask
from tenable_net.gui.models import DataFrameModel, MaskFilterProxy
from tenable_net.gui.widgets import SEVERITY_COLORS, FindingDetail, dot_icon, fit_columns, make_table
from tenable_net.normalize import SEVERITY_ORDER

FINDING_TABLE_COLUMNS = [
    "risk", "severity", "hostname", "ip", "vendor", "plugin_id", "plugin_name", "vpr", "cves",
    "exploit_available", "port", "state", "days_open", "last_found",
]


class FindingsPanel(QSplitter):
    """A findings table with a detail pane underneath. Reused by the Findings and Devices tabs."""

    def __init__(self, columns=FINDING_TABLE_COLUMNS, parent=None):
        super().__init__(Qt.Vertical, parent)
        self.model = DataFrameModel(columns=columns)
        self._columns = columns
        self.proxy = MaskFilterProxy(self)
        self.proxy.setSourceModel(self.model)
        self.table = make_table(self.proxy, stretch_column="plugin_name")
        self.detail = FindingDetail()
        self.addWidget(self.table)
        self.addWidget(self.detail)
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
        if "plugin_id" in df and "hostname" in df and not df.empty:
            self.detail.shared_counts = df.groupby("plugin_id")["hostname"].nunique().to_dict()
        fit_columns(self.table, max_width=200, caps={"cves": 150})
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


class FindingsTab(QWidget):
    count_changed = Signal(int, int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.df = pd.DataFrame()
        self._debounce = QTimer(self, singleShot=True, interval=200)
        self._debounce.timeout.connect(self.apply_filters)

        # --- sidebar -------------------------------------------------------
        self.search = QLineEdit(placeholderText="Search device, IP, plugin, CVE…", clearButtonEnabled=True)
        self.search.textChanged.connect(self._debounce.start)

        sev_box = QGroupBox("Severity")
        sev_layout = QVBoxLayout(sev_box)
        self.sev_checks = {}
        for sev in SEVERITY_ORDER:
            cb = QCheckBox(sev.title())
            cb.setChecked(True)
            cb.setIcon(dot_icon(SEVERITY_COLORS[sev]))
            cb.toggled.connect(self.apply_filters)
            sev_layout.addWidget(cb)
            self.sev_checks[sev] = cb

        state_box = QGroupBox("State")
        state_layout = QVBoxLayout(state_box)
        self.state_checks = {}
        for state in ("OPEN", "REOPENED", "FIXED"):
            cb = QCheckBox(state.title())
            cb.setChecked(True)
            cb.toggled.connect(self.apply_filters)
            state_layout.addWidget(cb)
            self.state_checks[state] = cb

        other_box = QGroupBox("More filters")
        form = QFormLayout(other_box)
        self.vendor = QComboBox()
        self.vendor.currentIndexChanged.connect(self.apply_filters)
        self.min_vpr = QDoubleSpinBox(minimum=0, maximum=10, singleStep=0.5, decimals=1)
        self.min_vpr.valueChanged.connect(self._debounce.start)
        self.exploitable = QCheckBox("Exploit available only")
        self.exploitable.toggled.connect(self.apply_filters)
        form.addRow("Vendor", self.vendor)
        form.addRow("Min VPR", self.min_vpr)
        form.addRow(self.exploitable)

        reset = QPushButton("Reset filters")
        reset.clicked.connect(self.reset_filters)
        export = QPushButton("Export view…")
        export.setToolTip("Save the rows currently shown to CSV or Excel")
        export.clicked.connect(self.export_view)
        self.count_label = QLabel()
        self.count_label.setWordWrap(True)

        sidebar = QWidget()
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(0, 0, 8, 0)
        for w in (self.search, sev_box, state_box, other_box, self.count_label, reset, export):
            side.addWidget(w)
        side.addStretch(1)
        sidebar.setFixedWidth(240)

        # --- main ----------------------------------------------------------
        self.panel = FindingsPanel()
        layout = QHBoxLayout(self)
        layout.addWidget(sidebar)
        layout.addWidget(self.panel, 1)

    def set_data(self, findings):
        self.df = findings
        self.vendor.blockSignals(True)
        self.vendor.clear()
        self.vendor.addItem("All vendors", "")
        for vendor, n in findings["vendor"].value_counts().items():
            self.vendor.addItem(f"{vendor} ({n})", vendor)
        self.vendor.blockSignals(False)
        counts = findings["severity"].astype(str).value_counts()
        for sev, cb in self.sev_checks.items():
            cb.setText(f"{sev.title()}  ({counts.get(sev, 0):,})")
        self.panel.set_frame(findings)
        self.apply_filters()

    def current_filters(self):
        return dict(
            severities=[s for s, cb in self.sev_checks.items() if cb.isChecked()],
            states=[s for s, cb in self.state_checks.items() if cb.isChecked()],
            vendor=self.vendor.currentData() or None,
            min_vpr=self.min_vpr.value(),
            exploitable_only=self.exploitable.isChecked(),
            text=self.search.text(),
        )

    def apply_filters(self):
        if self.df.empty:
            mask = np.zeros(0, dtype=bool)
        else:
            mask = filter_mask(self.panel.model.frame, **self.current_filters())
        self.panel.set_mask(mask)
        shown, total = int(mask.sum()), len(mask)
        devices = self.panel.model.frame.loc[mask, "hostname"].nunique() if total else 0
        self.count_label.setText(f"<b>{shown:,}</b> of {total:,} findings<br>on <b>{devices:,}</b> devices")
        self.count_changed.emit(shown, total)

    def reset_filters(self):
        for w in (*self.sev_checks.values(), *self.state_checks.values(), self.exploitable,
                  self.vendor, self.min_vpr, self.search):
            w.blockSignals(True)
        for cb in (*self.sev_checks.values(), *self.state_checks.values()):
            cb.setChecked(True)
        self.exploitable.setChecked(False)
        self.vendor.setCurrentIndex(0)
        self.min_vpr.setValue(0)
        self.search.clear()
        for w in (*self.sev_checks.values(), *self.state_checks.values(), self.exploitable,
                  self.vendor, self.min_vpr, self.search):
            w.blockSignals(False)
        self.apply_filters()

    def show_query(self, text, **filters):
        """Reset filters and apply a search (used for drill-down from the Overview)."""
        self.reset_filters()
        if filters.get("severity"):
            for sev, cb in self.sev_checks.items():
                cb.setChecked(sev == filters["severity"])
        if filters.get("exploitable"):
            self.exploitable.setChecked(True)
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
