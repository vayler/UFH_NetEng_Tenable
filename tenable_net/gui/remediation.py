"""Remediation plan: fixes ranked by how much risk they remove, with per-device detail and export."""

import html

import numpy as np
import pandas as pd
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QComboBox, QFileDialog, QFrame, QHBoxLayout, QVBoxLayout, QWidget

from tenable_net import remediation, reports
from tenable_net.gui import theme
from tenable_net.gui.models import DataFrameModel, MaskFilterProxy
from tenable_net.gui.widgets import SearchField, Splitter, button, divider, fit_columns, label, make_table

ACTION_TABLE = ["rank", "type", "title", "confidence", "devices", "findings", "critical", "high", "priority"]
CONFIDENCE_HELP = {
    "Confirmed": "Every advisory's fixed release (from plugin output) is at or below the target release.",
    "Likely": "Cisco suggests this release for the model; fixed releases weren't in the pulled data (pull with "
              "plugin output to confirm).",
    "Check": "Some advisories list a fixed release newer than Cisco's suggestion: check before scheduling.",
    "Find release": "No suggested release known for this model: pick one that fixes every listed advisory.",
}


class RemediationView(QWidget):
    device_activated = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.actions = pd.DataFrame(columns=["rank", *remediation.ACTION_COLUMNS])
        self.members = {}
        self.total_risk = 0.0

        self.type_filter = QComboBox()
        self.type_filter.addItems(["All actions", "OS upgrade", "Configuration", "Hardware"])
        self.vendor_filter = QComboBox()
        self.search = SearchField("Filter actions by model, plugin, vendor…")
        self.search.setMaximumWidth(340)
        for w in (self.type_filter, self.vendor_filter):
            w.currentIndexChanged.connect(self._filter)
        self.search.textChanged.connect(self._filter)
        export_all = button("Export plan…", "ghost", "export", "All actions and their devices to Excel")
        export_all.clicked.connect(self.export_plan)
        bar = QFrame()
        bar.setObjectName("Toolbar")
        filters = QHBoxLayout(bar)
        filters.setContentsMargins(14, 10, 10, 10)
        filters.setSpacing(6)
        filters.addWidget(self.search, 1)
        filters.addWidget(self.type_filter)
        filters.addWidget(self.vendor_filter)
        filters.addStretch(1)
        filters.addWidget(export_all)

        self.summary = label("", "body", "Muted", wrap=True)
        self.summary.setTextFormat(Qt.RichText)
        self.summary.setContentsMargins(16, 10, 16, 8)

        self.model = DataFrameModel()
        self.proxy = MaskFilterProxy(self)
        self.proxy.setSourceModel(self.model)
        self.table = make_table(self.proxy, stretch_column="title")
        self.table.setSortingEnabled(False)
        self.proxy.sort(-1)  # keep the plan's rank order (make_table enabled header sorting)
        self.table.selectionModel().currentRowChanged.connect(self._on_action)

        # detail
        self.detail_title = label("", "section", wrap=True)
        self.detail_info = label("", "body", wrap=True)
        self.detail_info.setTextFormat(Qt.RichText)
        self.items_model = DataFrameModel()
        self.items_view = make_table(self.items_model, stretch_column="cves")
        self.items_view.doubleClicked.connect(self._item_clicked)
        self.items_view.setToolTip("Double-click a device to open it")
        self.export_action_button = button("Export devices…", "ghost", "export", "This action's devices to CSV, "
                                                                                 "for a change ticket")
        self.export_action_button.clicked.connect(self.export_action)
        card = QWidget()
        cv = QVBoxLayout(card)
        cv.setContentsMargins(0, 12, 0, 0)
        cv.setSpacing(6)
        title_row = QHBoxLayout()
        title_row.setContentsMargins(16, 0, 10, 0)
        title_row.addWidget(self.detail_title, 1)
        title_row.addWidget(self.export_action_button, 0, Qt.AlignTop)
        cv.addLayout(title_row)
        self.detail_info.setContentsMargins(16, 0, 16, 6)
        cv.addWidget(self.detail_info)
        cv.addWidget(self.items_view, 1)

        split = Splitter(Qt.Vertical, line=True)
        split.addWidget(self.table)
        split.addWidget(card)
        split.setSizes([360, 440])
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(bar)
        layout.addWidget(divider())
        layout.addWidget(self.summary)
        layout.addWidget(split, 1)

    def set_data(self, actions, members, total_risk):
        self.actions, self.members, self.total_risk = actions, members, float(total_risk or 0)
        self.vendor_filter.blockSignals(True)
        self.vendor_filter.clear()
        self.vendor_filter.addItem("All vendors", "")
        for vendor in sorted({v for vs in actions["vendor"].dropna() for v in str(vs).split(", ") if v}):
            self.vendor_filter.addItem(vendor, vendor)
        self.vendor_filter.blockSignals(False)
        self.model.set_frame(actions, ACTION_TABLE)
        fit_columns(self.table, max_width=180)
        top = actions.head(5)["risk_removed"].sum() if not actions.empty else 0
        share = f"{top / self.total_risk:.0%}" if self.total_risk else "–"
        by_type = actions["type"].value_counts() if not actions.empty else {}
        text = theme.tokens()["text"]
        self.summary.setText(
            f"<span style='color:{text}'>{len(actions)} actions</span> · {by_type.get('OS upgrade', 0)} OS upgrades, "
            f"{by_type.get('Configuration', 0)} configuration fixes, {by_type.get('Hardware', 0)} hardware. "
            f"Ranked by risk removed per device touched; the top 5 address about "
            f"<span style='color:{text}'>{share}</span> of total finding risk.")
        self._filter()

    def _filter(self, *_):
        frame = self.model.frame
        for combo in (self.type_filter, self.vendor_filter):
            active = combo.currentIndex() > 0
            if bool(combo.property("active")) != active:
                combo.setProperty("active", active)
                theme.repolish(combo)
        if frame.empty:
            self.proxy.set_mask(np.zeros(0, dtype=bool))
            self._show(None)
            return
        mask = np.ones(len(frame), dtype=bool)
        if self.type_filter.currentIndex() > 0:
            mask &= (frame["type"] == self.type_filter.currentText()).to_numpy()
        vendor = self.vendor_filter.currentData()
        if vendor:
            mask &= frame["vendor"].fillna("").str.contains(vendor, regex=False).to_numpy()
        text = self.search.text().strip().lower()
        if text:
            hay = (frame["title"].fillna("") + " " + frame["vendor"].fillna("") + " " + frame["target"].fillna(""))
            mask &= hay.str.lower().str.contains(text, regex=False).to_numpy()
        self.proxy.set_mask(mask)
        if self.proxy.rowCount():
            self.table.selectRow(0)
        else:
            self._show(None)

    def select_action(self, action_id):
        self.type_filter.setCurrentIndex(0)
        self.vendor_filter.setCurrentIndex(0)
        self.search.clear()
        frame = self.model.frame
        for r in range(self.proxy.rowCount()):
            if frame.iloc[self.proxy.source_row(r)]["id"] == action_id:
                self.table.selectRow(r)
                return True
        return False

    def current_action(self):
        idx = self.table.currentIndex()
        if not idx.isValid():
            return None
        return self.model.frame.iloc[self.proxy.mapToSource(idx).row()]

    def _on_action(self, *_):
        self._show(self.current_action())

    def _show(self, action):
        self.export_action_button.setEnabled(action is not None)
        if action is None:
            self.detail_title.setText("No action selected")
            self.detail_info.setText("")
            self.items_model.set_frame(pd.DataFrame())
            return
        t = theme.tokens()
        self.detail_title.setText(f"{action['title']}")
        meta = [f"<span style='color:{t['text_muted']}'>#{action['rank']}</span>",
                f"<b>{html.escape(action['type'])}</b>"]
        if action["target"]:
            meta.append(f"target <b>{html.escape(action['target'])}</b>")
        meta.append(f"{action['devices']} device{'s' if action['devices'] != 1 else ''}")
        meta.append(f"{action['findings']} finding{'s' if action['findings'] != 1 else ''}")
        crit, high = int(action["critical"]), int(action["high"])
        meta.append(theme.severity_badge("critical", f"{crit} critical") + " &nbsp;"
                    + theme.severity_badge("high", f"{high} high"))
        meta.append(f"risk removed {action['risk_removed']:g}")
        lines = ["&nbsp; · &nbsp;".join(meta)]
        if action["confidence"]:
            lines.append(f"{theme.status_badge(html.escape(action['confidence']))} "
                         f"<span style='color:{t['text_muted']}'>— "
                         f"{html.escape(CONFIDENCE_HELP.get(action['confidence'], ''))}</span>")
        detail = html.escape(str(action["detail"] or "")).replace("\n", "<br>")
        if detail:
            lines.append(f"<span style='color:{t['text_muted']}'>{detail}</span>")
        self.detail_info.setText("<br>".join(lines))
        items = remediation.action_items(action.to_dict(), self.members.get(action["id"], pd.DataFrame()))
        self.items_model.set_frame(items)
        fit_columns(self.items_view, max_width=200)

    def _item_clicked(self, index):
        frame = self.items_model.frame
        if index.isValid() and index.row() < len(frame) and "hostname" in frame:
            self.device_activated.emit(str(frame.iloc[index.row()]["hostname"]))

    # ---- export -------------------------------------------------------------------------
    def export_action(self):
        action = self.current_action()
        if action is None:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export action", f"action_{action['id']}.csv", "CSV (*.csv)")
        if path:
            remediation.action_items(action.to_dict(), self.members.get(action["id"], pd.DataFrame())).to_csv(
                path, index=False)

    def export_plan(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export remediation plan", "remediation_plan.xlsx",
                                              "Excel (*.xlsx)")
        if not path:
            return
        rows = []
        for action in self.actions.to_dict("records"):
            items = remediation.action_items(action, self.members.get(action["id"], pd.DataFrame()))
            for item in items.to_dict("records"):
                rows.append({"rank": action["rank"], "action": action["title"], "type": action["type"],
                             "confidence": action["confidence"], **item})
        with pd.ExcelWriter(path, engine="openpyxl") as writer:
            reports.excel_safe(self.actions.drop(columns=["detail"])).to_excel(writer, sheet_name="Actions", index=False)
            reports.excel_safe(pd.DataFrame(rows)).to_excel(writer, sheet_name="Devices per action", index=False)
