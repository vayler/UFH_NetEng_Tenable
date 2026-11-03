"""Pull-from-Tenable and connection-settings dialogs."""

import html
import os
import re

from dotenv import load_dotenv
from PySide6.QtCore import QSize, Qt
from PySide6.QtWidgets import (
    QCheckBox, QDialog, QFormLayout, QHBoxLayout, QLineEdit, QListWidget, QListWidgetItem, QMessageBox,
    QPlainTextEdit, QProgressBar, QSpinBox, QStackedWidget, QVBoxLayout, QWidget,
)

from tenable_net import akips, cisco, client, export, inventory
from tenable_net.gui import icons, theme
from tenable_net.gui.widgets import ToggleChip, button, divider, label, severity_icon, start_worker
from tenable_net.normalize import SEVERITY_ORDER


def _section(title, note=None):
    box = QVBoxLayout()
    box.setSpacing(6)
    box.addWidget(label(title, "body", weight="medium"))
    if note:
        box.addWidget(label(note, "caption", "Muted", wrap=True))
    return box


class PullDialog(QDialog):
    """Choose export filters, run the export in the background, and report progress."""

    def __init__(self, cache_dir, parent=None, client_factory=client.get_client,
                 akips_factory=None, cisco_factory=None):
        super().__init__(parent)
        # Factories return a client, or None when that source isn't configured.
        self.akips_factory = akips_factory or (lambda: akips.get_client() if akips.configured() else None)
        self.cisco_factory = cisco_factory or (lambda: cisco.get_client() if cisco.configured() else None)
        self.setWindowTitle("Pull from Tenable")
        self.setMinimumWidth(560)
        self.cache_dir = cache_dir
        self.client_factory = client_factory
        self.worker = None
        self.meta = None

        self.sev_checks = {}
        sev_row = QHBoxLayout()
        sev_row.setSpacing(6)
        for sev in SEVERITY_ORDER:
            chip = ToggleChip(sev.title())
            chip.setIcon(severity_icon(sev))
            chip.setChecked(sev != "info")
            sev_row.addWidget(chip)
            self.sev_checks[sev] = chip
        sev_row.addStretch(1)

        self.state_checks = {}
        state_row = QHBoxLayout()
        state_row.setSpacing(6)
        for state in ("open", "reopened", "fixed"):
            chip = ToggleChip(state.title())
            chip.setChecked(state != "fixed")
            state_row.addWidget(chip)
            self.state_checks[state] = chip
        state_row.addStretch(1)

        self.since = QSpinBox(minimum=0, maximum=3650, suffix=" days", specialValueText="Any time")
        self.since.setToolTip("Only findings seen within this many days (0 = no limit)")
        self.since.setMinimumWidth(130)
        self.plugin_output = QCheckBox("Include plugin output (bigger and slower; confirms fixed releases)")
        self.assets = QCheckBox("Refresh the asset inventory")
        self.assets.setChecked(True)
        self.hardware = QCheckBox("Hardware inventory (AKiPS + Tenable plugin output)")
        self.hardware.setChecked(True)
        self.hardware.setToolTip("Model and serial per chassis/stack member. AKiPS is used when configured in Settings.")
        self.lifecycle = QCheckBox("Cisco enrichment: contracts and software suggestions")
        self.lifecycle.setChecked(cisco.configured())
        self.lifecycle.setToolTip("Uses the Cisco APIs chosen in Settings." if cisco.configured() else
                                  "Add Cisco API credentials in Settings to enable.")
        self.recheck = QCheckBox("Re-query Cisco even if results are cached (normally kept 7 days)")
        self.hardware.toggled.connect(lambda on: self.lifecycle.setEnabled(on))
        self.lifecycle.toggled.connect(lambda on: self.recheck.setEnabled(on))
        self.recheck.setEnabled(self.lifecycle.isChecked())
        self.warnings = 0

        since_row = QHBoxLayout()
        since_row.addWidget(label("Last seen within", "body"))
        since_row.addWidget(self.since)
        since_row.addStretch(1)

        self.progress = QProgressBar()
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        self.progress.setVisible(False)  # shown once a pull starts
        self.status = label("Your previous data is kept if the pull is cancelled or fails.", "caption", "Muted",
                            wrap=True)
        self.status.setTextFormat(Qt.RichText)
        self.log = QPlainTextEdit(readOnly=True)
        self.log.setObjectName("Log")
        self.log.setFont(theme.mono_font())
        self.log.setMaximumHeight(130)
        self.log.setVisible(False)

        self.start_button = button("Start pull", "primary", "pull")
        self.start_button.setDefault(True)
        self.cancel_button = button("Cancel")
        self.start_button.clicked.connect(self.start)
        self.cancel_button.clicked.connect(self.cancel)
        buttons = QHBoxLayout()
        buttons.addWidget(self.progress, 1)
        buttons.addStretch(0)
        buttons.addSpacing(16)
        buttons.addWidget(self.cancel_button)
        buttons.addWidget(self.start_button)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)
        layout.addWidget(label("Pull from Tenable", "headline"))
        layout.addWidget(label("Exports findings with Tenable's bulk export API, then optionally refreshes the hardware "
                               "inventory and Cisco data.", "body", "Muted", wrap=True))
        severity = _section("Severity")
        severity.addLayout(sev_row)
        layout.addLayout(severity)
        state = _section("State")
        state.addLayout(state_row)
        layout.addLayout(state)
        options = _section("Options")
        options.addLayout(since_row)
        for w in (self.plugin_output, self.assets, self.hardware, self.lifecycle, self.recheck):
            options.addWidget(w)
        layout.addLayout(options)
        layout.addWidget(divider())
        layout.addWidget(self.status)
        layout.addWidget(self.log)
        layout.addLayout(buttons)

    def options(self):
        return dict(
            severity=[s for s, cb in self.sev_checks.items() if cb.isChecked()],
            state=[s for s, cb in self.state_checks.items() if cb.isChecked()],
            since_days=self.since.value() or None,
            include_output=self.plugin_output.isChecked(),
            skip_assets=not self.assets.isChecked(),
        )

    def _controls(self):
        return (self.start_button, *self.sev_checks.values(), *self.state_checks.values(), self.since,
                self.plugin_output, self.assets, self.hardware, self.lifecycle, self.recheck)

    def start(self):
        opts = self.options()
        if not opts["severity"] or not opts["state"]:
            QMessageBox.warning(self, "Pull", "Pick at least one severity and one state.")
            return
        try:
            tio = self.client_factory()
        except client.MissingCredentials:
            QMessageBox.warning(self, "API keys needed", "Add your Tenable API keys in Settings first.")
            if SettingsDialog(self, cache_dir=self.cache_dir).exec() != QDialog.Accepted:
                return
            tio = self.client_factory()

        akips_client = cisco_client = None
        if self.hardware.isChecked():
            try:
                akips_client = self.akips_factory()
                cisco_client = self.cisco_factory() if self.lifecycle.isChecked() else None
            except client.MissingCredentials as exc:
                self._log(f"WARNING: {exc}")

        def job(worker):
            cancelled = lambda: worker.cancel_requested  # noqa: E731
            meta = export.pull(
                tio, cache_dir=self.cache_dir, log=worker.log.emit, progress=worker.progress.emit,
                cancelled=cancelled, **opts,
            )
            if self.hardware.isChecked():
                inventory.refresh_all(
                    self.cache_dir, tio=tio, akips_client=akips_client, cisco_client=cisco_client,
                    force_cisco=self.recheck.isChecked(), strict=False, log=worker.log.emit, progress=worker.progress.emit, cancelled=cancelled,
                )
            return meta

        for w in self._controls():
            w.setEnabled(False)
        self.progress.setRange(0, 0)  # indeterminate: Tenable doesn't report a total up front
        self.progress.setVisible(True)
        self.log.setVisible(True)
        self.status.setText("Requesting export from Tenable… large exports can take several minutes.")
        self.worker = start_worker(job, self, on_done=self._done, on_error=self._error,
                                   on_log=self._log, on_progress=self._progress)

    def _log(self, message):
        text = re.sub(r"\[/?[a-z ]+\]", "", str(message))  # drop rich markup
        if "WARNING" in text:
            self.warnings += 1
        self.log.appendPlainText(text)

    def _progress(self, stage, count):
        self.status.setText(f"Downloading {stage}: {count:,} records…")

    def _done(self, meta):
        self.meta = meta
        self.progress.setRange(0, 1)
        self.progress.setValue(1)
        done = f"Done: {meta['vuln_count']:,} findings, {meta['asset_count']:,} assets."
        if not self.warnings:
            self.status.setText(done)
            self.accept()
            return
        # Keep the dialog open so warnings (e.g. a Cisco API that isn't enabled) can be read.
        t = theme.tokens()
        self.status.setText(f"<span style='color:{t['text']}'>{done}</span> <span style='color:{t['warn']}'>"
                            f"Finished with {self.warnings} warning(s); see the log below.</span>")
        self.log.setMaximumHeight(16777215)
        self.cancel_button.setText("Close")
        self.cancel_button.setEnabled(True)

    def _error(self, message):
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        if message.startswith("ExportCancelled"):
            self.status.setText("Cancelled. The previous cached data was kept.")
            self.reject()
            return
        self.status.setText("Pull failed.")
        self._log(message)
        for w in self._controls():
            w.setEnabled(True)
        self.lifecycle.setEnabled(self.hardware.isChecked())
        QMessageBox.critical(self, "Pull failed", message.split("\n\n")[0])

    def cancel(self):
        if self.meta is not None:  # finished with warnings: "Close" keeps the pulled data
            self.accept()
            return
        if self.worker and self.worker.thread.isRunning():
            self.worker.cancel_requested = True
            self.cancel_button.setEnabled(False)
            self.status.setText("Cancelling after the current chunk…")
        else:
            self.reject()

    def closeEvent(self, event):
        if self.worker and self.worker.thread.isRunning():
            self.cancel()
            event.ignore()
        else:
            super().closeEvent(event)


class _ServicePage(QWidget):
    """One page of the settings dialog: a form of .env fields plus a Test button run off-thread."""

    def __init__(self, title, fields, hint, test_fn, choices=None, parent=None):
        """choices: optional (env_key, [(value, label)], defaults) rendered as checkboxes and saved as a
        comma-separated list, e.g. CISCO_APIS=sn2info,software."""
        super().__init__(parent)
        self.fields = {}
        self.test_fn = test_fn
        self.worker = None
        self.choice_key, self.choice_checks = None, {}
        form = QFormLayout()
        form.setHorizontalSpacing(16)
        form.setVerticalSpacing(10)
        form.setLabelAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        for key, field_label, secret in fields:
            edit = QLineEdit(os.getenv(key) or "")
            if secret:
                edit.setEchoMode(QLineEdit.Password)
            self.fields[key] = edit
            form.addRow(label(field_label, "body", "Muted"), edit)
        show = QCheckBox("Show secrets")
        show.toggled.connect(self._toggle_echo)
        form.addRow("", show)
        self._secret_keys = [k for k, _l, secret in fields if secret]
        choice_box = None
        if choices:
            self.choice_key, options, defaults = choices
            current = os.getenv(self.choice_key)
            selected = set(defaults) if current is None else {c.strip() for c in current.split(",")}
            choice_box = _section("APIs your Cisco API app has", "Test connection ticks the ones that respond.")
            for value, text in options:
                cb = QCheckBox(text)
                cb.setChecked(value in selected)
                choice_box.addWidget(cb)
                self.choice_checks[value] = cb
        note = label(hint, "body", "Muted", wrap=True)
        note.setTextFormat(Qt.RichText)
        self.test_button = button("Test connection", icon_name="reload")
        self.test_button.clicked.connect(self.test)
        self.result = label("", "body", wrap=True)
        self.result.setTextFormat(Qt.RichText)
        row = QHBoxLayout()
        row.addWidget(self.test_button, 0, Qt.AlignTop)
        row.addSpacing(8)
        row.addWidget(self.result, 1)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 12)
        layout.setSpacing(14)
        layout.addWidget(label(title, "title"))
        layout.addWidget(note)
        layout.addLayout(form)
        if choice_box is not None:
            layout.addLayout(choice_box)
        layout.addLayout(row)
        layout.addStretch(1)

    def _toggle_echo(self, show):
        for key in self._secret_keys:
            self.fields[key].setEchoMode(QLineEdit.Normal if show else QLineEdit.Password)

    def values(self):
        values = {k: e.text().strip() for k, e in self.fields.items()}
        if self.choice_key:
            values[self.choice_key] = ",".join(v for v, cb in self.choice_checks.items() if cb.isChecked())
        return values

    def test(self):
        values = self.values()
        self.test_button.setEnabled(False)
        self.result.setText(f"<span style='color:{theme.tokens()['text_muted']}'>Connecting…</span>")
        self.worker = start_worker(lambda _w: self.test_fn(values), self, on_done=self._ok, on_error=self._fail)

    def _ok(self, message):
        self.test_button.setEnabled(True)
        if isinstance(message, dict):  # per-API report: {"html", "apis": {key: True/False}}
            for key, ok in message.get("apis", {}).items():
                if key in self.choice_checks:
                    self.choice_checks[key].setChecked(ok)
            self.result.setText(message["html"])
            return
        self.result.setText(f"<span style='color:{theme.tokens()['good']}'>✓ {html.escape(message)}</span>")

    def _fail(self, message):
        self.test_button.setEnabled(True)
        first = message.split("\n\n")[0].splitlines()
        text = next((line for line in reversed(first) if line.strip()), message)
        text = re.sub(r"^\w+(Error|Exception): ", "", text)
        self.result.setText(f"<span style='color:{theme.tokens()['bad']}'>{html.escape(text)}</span>")


def _test_tenable(v):
    details = client.get_client(v["TIO_ACCESS_KEY"], v["TIO_SECRET_KEY"]).session.details()
    return f"Connected as {details.get('username') or details.get('email') or 'OK'}"


def _test_akips(v):
    c = akips.get_client(v["AKIPS_URL"], v["AKIPS_USER"] or "api-ro", v["AKIPS_PASSWORD"])
    return f"Connected: {c.test():,} devices"


def _test_cisco(v, cache_dir=None):
    """Token + every API. Uses a real serial / model from the cached inventory when there is one.

    Returns a per-API report; the Settings page ticks the APIs that answered and unticks the ones
    that were refused, so you don't have to know which APIs your Cisco API app includes."""
    c = cisco.get_client(v["CISCO_CLIENT_ID"], v["CISCO_CLIENT_SECRET"])
    serial = pid = None
    if cache_dir is not None:
        try:
            serial, pid = inventory.sample_cisco_keys(cache_dir)
        except Exception:  # noqa: BLE001 - the probes still work without inventory
            pass
    results = cisco.diagnose(c, serial=serial, pid=pid)
    if results[0][2] is False:
        raise RuntimeError(f"Token: {results[0][3]}")
    t = theme.tokens()
    lines = []
    for _key, name, ok, detail in results:
        color, mark = {True: (t["good"], "✓"), False: (t["bad"], "✕"), None: (t["text_muted"], "–")}[ok]
        lines.append(f"<span style='color:{color}'>{mark}</span>&nbsp; <b>{html.escape(name)}</b>"
                     f"<span style='color:{t['text_muted']}'>: {html.escape(detail)}</span>")
    return {"html": "<br>".join(lines),
            "apis": {key: ok for key, _n, ok, _d in results if key in cisco.API_NAMES and ok is not None}}


class SettingsDialog(QDialog):
    """Tenable, AKiPS and Cisco API credentials, each with a connection test. Saved to .env."""

    def __init__(self, parent=None, cache_dir=None):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.resize(780, 520)
        load_dotenv(client.env_path())
        self.pages = {
            "Tenable": _ServicePage(
                "Tenable Vulnerability Management",
                [("TIO_ACCESS_KEY", "Access key", True), ("TIO_SECRET_KEY", "Secret key", True)],
                "Generate keys in Tenable under <i>Settings → My Account → API Keys</i>.", _test_tenable),
            "AKiPS": _ServicePage(
                "AKiPS",
                [("AKIPS_URL", "URL", False), ("AKIPS_USER", "API user", False), ("AKIPS_PASSWORD", "Password", True)],
                "Optional. A read-only API user (e.g. <code>api-ro</code>). Supplies model and serial for "
                "every chassis / stack member via ENTITY-MIB.", _test_akips),
            "Cisco": _ServicePage(
                "Cisco Support APIs",
                [("CISCO_CLIENT_ID", "Client ID", False), ("CISCO_CLIENT_SECRET", "Client secret", True)],
                "Optional. Cisco Support API app credentials (API Console, client-credentials grant). "
                "Override endpoints with CISCO_TOKEN_URL / CISCO_API_BASE in .env if needed.",
                lambda v: _test_cisco(v, cache_dir),
                choices=("CISCO_APIS", [
                    ("sn2info", "Serial Number to Information: contract coverage, contract number, base PID"),
                    ("software", "Software Suggestion v2: Cisco-suggested releases vs. what devices run"),
                    ("eox", "EoX: end-of-sale / last-date-of-support dates"),
                ], cisco.DEFAULT_APIS)),
        }
        self.nav = QListWidget()
        self.nav.setObjectName("SettingsNav")
        self.nav.setFixedWidth(190)
        self.nav.setIconSize(QSize(16, 16))
        self.stack = QStackedWidget()
        t = theme.tokens()
        for (name, page), icon_name in zip(self.pages.items(), ("shield", "database", "layers")):
            item = QListWidgetItem(icons.icon(icon_name, t["text_muted"], active_color=t["text"]), name)
            item.setSizeHint(QSize(0, 32))
            self.nav.addItem(item)
            self.stack.addWidget(page)
        self.nav.currentRowChanged.connect(self.stack.setCurrentIndex)
        self.nav.setCurrentRow(0)
        self.nav.setStyleSheet(
            f"QListWidget#SettingsNav {{ background: {t['surface_alt']}; border: none; "
            f"border-right: 1px solid {t['border']}; padding: 12px 8px; }}"
            f"QListWidget#SettingsNav::item {{ border-radius: 6px; padding: 0 8px; color: {t['text_muted']}; }}"
            f"QListWidget#SettingsNav::item:hover {{ background: {t['hover']}; color: {t['text']}; }}"
            f"QListWidget#SettingsNav::item:selected {{ background: {t['active']}; color: {t['text']}; }}")
        self.tabs = self.stack  # older name

        where = label("", "caption", "Muted")
        where.setText("Saved to " + where.fontMetrics().elidedText(str(client.env_path()), Qt.ElideMiddle, 380))
        where.setToolTip(str(client.env_path()))
        cancel = button("Cancel")
        cancel.clicked.connect(self.reject)
        save = button("Save", "primary")
        save.setDefault(True)
        save.clicked.connect(self.save)
        footer = QHBoxLayout()
        footer.setContentsMargins(24, 12, 24, 16)
        footer.addWidget(where, 1)
        footer.addWidget(cancel)
        footer.addWidget(save)
        right = QVBoxLayout()
        right.setContentsMargins(0, 0, 0, 0)
        right.setSpacing(0)
        right.addWidget(self.stack, 1)
        right.addWidget(divider())
        right.addLayout(footer)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self.nav)
        layout.addLayout(right, 1)

    def save(self):
        values = {}
        for page in self.pages.values():
            values.update(page.values())
        tenable = (values["TIO_ACCESS_KEY"], values["TIO_SECRET_KEY"])
        if any(tenable) and not all(tenable):
            QMessageBox.warning(self, "Settings", "Enter both Tenable keys, or neither.")
            return
        client.save_env({k: v for k, v in values.items() if v or k == "CISCO_APIS"})
        self.accept()

