"""Qt table models over pandas DataFrames."""

import math

import numpy as np
import pandas as pd
from PySide6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt
from PySide6.QtGui import QColor

from tenable_net import glossary
from tenable_net.gui import theme
from tenable_net.normalize import SEVERITY_ORDER

SORT_ROLE = Qt.UserRole + 1
RAW_ROLE = Qt.UserRole + 2

HEADERS = {
    "hostname": "Device", "ip": "IP", "os": "OS", "vendor": "Vendor",
    "plugin_id": "Plugin", "plugin_name": "Name", "plugin_family": "Family",
    "severity": "Severity", "vpr": "VPR", "cvss3": "CVSSv3", "cves": "CVEs",
    "exploit_available": "Exploit", "state": "State", "port": "Port", "protocol": "Proto",
    "first_found": "First found", "last_found": "Last found", "devices": "Devices",
    "critical": "Crit", "high": "High", "medium": "Med", "low": "Low", "info": "Info",
    "total": "Total", "max_vpr": "Max VPR", "exploitable": "Exploitable", "findings": "Findings",
    "last_seen": "Last seen", "model": "Model", "lifecycle": "Lifecycle", "ldos": "LDoS",
    "contract": "Contract", "contract_end": "Contract ends", "sw_status": "Software",
    "recommended_sw": "Cisco suggested", "sw_version": "Running", "akips_device": "AKiPS device",
    "with_serial": "With serial", "match_method": "Matched by", "members": "Members", "sys_name": "sysName",
    "sys_descr": "sysDescr", "stage": "Stage", "reason": "Reason", "models": "Models", "chassis": "Chassis",
    "risk": "Risk", "risk_band": "Risk band", "days_open": "Days open", "top_finding": "Top finding",
    "change": "Change", "fixed": "Fixed", "mean_days": "Mean days", "median_days": "Median days",
    "rank": "#", "type": "Type", "title": "Action", "confidence": "Confidence", "priority": "Priority",
    "risk_removed": "Risk removed", "target": "Target", "running": "Running", "worst": "Worst",
    "plugins": "Plugins",
}
STATUS_COLUMNS = ("lifecycle", "contract", "sw_status", "risk_band", "stage", "change", "confidence")
# Identifiers, addresses and dates are secondary information: drawn in the muted text colour.
MUTED_COLUMNS = ("ip", "plugin_id", "port", "protocol", "first_found", "last_found", "last_seen", "days_open",
                 "member", "source", "contract_number", "akips_device", "match_method", "rank", "contract_end", "ldos",
                 "service_level")
LEFT_ALIGNED = ("plugin_id", "first_found", "last_found", "last_seen", "risk", "contract_end", "ldos")


def _is_missing(value):
    if value is None or value is pd.NaT:
        return True
    try:
        return bool(pd.isna(value))
    except (TypeError, ValueError):
        return False


def is_true(value):
    """True for Python/numpy True; False for False, None, NaN."""
    return not _is_missing(value) and bool(value) is True


def display(column, value):
    if _is_missing(value):
        return ""
    if isinstance(value, pd.Timestamp):
        return value.strftime("%Y-%m-%d")
    if column == "exploit_available":
        return "Yes" if is_true(value) else ""
    if column == "port" and value == 0:
        return ""
    if isinstance(value, float):
        return str(int(value)) if value.is_integer() and column not in ("vpr", "cvss3", "max_vpr") else f"{value:.1f}"
    return str(value)


def sort_key(column, value, numeric):
    """A key Qt can compare. Keys within a column always share one type (float or str)."""
    if column == "severity":
        return float(SEVERITY_ORDER.index(str(value))) if str(value) in SEVERITY_ORDER else 99.0
    if _is_missing(value):
        return -math.inf if numeric else ""
    if isinstance(value, pd.Timestamp):
        return value.timestamp()
    if isinstance(value, (bool, np.bool_)):
        return int(value)
    if numeric and isinstance(value, (int, float, np.integer, np.floating)):
        return float(value)
    return str(value).lower()


class DataFrameModel(QAbstractTableModel):
    def __init__(self, df=None, columns=None, parent=None):
        super().__init__(parent)
        self._df = pd.DataFrame()
        self._columns = []
        self.set_frame(df if df is not None else pd.DataFrame(), columns)

    def set_frame(self, df, columns=None):
        self.beginResetModel()
        self._df = df.reset_index(drop=True)
        self._columns = [c for c in (columns or list(df.columns)) if c in df.columns]
        # Pre-extract columns as lists: much faster than DataFrame.iat in data().
        self._values = {c: self._df[c].tolist() for c in self._columns}
        self._numeric = {
            c: pd.api.types.is_numeric_dtype(self._df[c]) or pd.api.types.is_datetime64_any_dtype(self._df[c])
            for c in self._columns
        }
        self.endResetModel()

    @property
    def frame(self):
        return self._df

    @property
    def columns(self):
        return self._columns

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self._df)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self._columns)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        column = self._columns[index.column()]
        value = self._values[column][index.row()]
        if role == Qt.DisplayRole:
            return display(column, value)
        if role == SORT_ROLE:
            return sort_key(column, value, self._numeric[column])
        if role == RAW_ROLE:
            return value
        if role == Qt.TextAlignmentRole:
            return self._alignment(column)
        if role == Qt.ForegroundRole and column in MUTED_COLUMNS:
            return QColor(theme.tokens()["text_muted"])
        if role == Qt.ToolTipRole and column in ("plugin_name", "cves", "os", "model"):
            return display(column, value)
        return None

    def _alignment(self, column):
        if self._numeric[column] and column not in LEFT_ALIGNED:
            return int(Qt.AlignRight | Qt.AlignVCenter)
        return int(Qt.AlignLeft | Qt.AlignVCenter)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.ToolTipRole and orientation == Qt.Horizontal:
            return glossary.tooltip(self._columns[section])
        if role == Qt.TextAlignmentRole and orientation == Qt.Horizontal and section < len(self._columns):
            return self._alignment(self._columns[section])
        if role != Qt.DisplayRole:
            return None
        if orientation == Qt.Horizontal:
            column = self._columns[section]
            return HEADERS.get(column, column.replace("_", " ").title())
        return str(section + 1)

    def column_index(self, name):
        return self._columns.index(name) if name in self._columns else -1

    def sort_keys(self, column):
        """A vectorised sort key for a column (severity by rank, text case-insensitive)."""
        series = self._df[column]
        if column == "severity":
            return series.astype(str).map({s: i for i, s in enumerate(SEVERITY_ORDER)}).fillna(99)
        if self._numeric[column]:
            return series
        return series.fillna("").astype(str).str.lower()

    def sort_frame(self, column, order, on_permute=None):
        """Sort the underlying frame in pandas (fast for 100k rows). on_permute(perm) is called with the new
        order (old row positions) before views are told, so a filter mask can be permuted to match."""
        if not 0 <= column < len(self._columns) or self._df.empty:
            return None
        keys = self.sort_keys(self._columns[column]).reset_index(drop=True)
        ascending = order == Qt.AscendingOrder
        perm = keys.sort_values(ascending=ascending, kind="stable", na_position="last").index.to_numpy()
        if on_permute is not None:
            on_permute(perm)
        self.layoutAboutToBeChanged.emit()
        self._df = self._df.iloc[perm].reset_index(drop=True)
        self._values = {c: self._df[c].tolist() for c in self._columns}
        self.layoutChanged.emit()
        return perm

    def sort(self, column, order=Qt.AscendingOrder):
        self.sort_frame(column, order)


class MaskFilterProxy(QSortFilterProxyModel):
    """Sort/filter proxy whose row filter is a precomputed boolean mask (fast for large frames)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._mask = None
        self.setSortRole(SORT_ROLE)

    def sort(self, column, order=Qt.AscendingOrder):
        """Sort the source DataFrame instead of comparing rows one by one in Python."""
        source = self.sourceModel()
        if source is None or not hasattr(source, "sort_frame"):
            return super().sort(column, order)

        def permute(perm):
            if self._mask is not None and len(self._mask) == len(perm):
                self._mask = self._mask[perm]

        source.sort_frame(column, order, on_permute=permute)
        self.set_mask(self._mask)  # re-filter against the new row order

    def set_mask(self, mask):
        if hasattr(self, "beginFilterChange"):  # Qt 6.9+
            self.beginFilterChange()
            self._mask = mask
            self.endFilterChange(QSortFilterProxyModel.Direction.Rows)
        else:
            self._mask = mask
            self.invalidateRowsFilter()

    def filterAcceptsRow(self, source_row, source_parent):
        if self._mask is None or source_row >= len(self._mask):
            return True
        return bool(self._mask[source_row])

    def source_row(self, proxy_row):
        return self.mapToSource(self.index(proxy_row, 0)).row()
