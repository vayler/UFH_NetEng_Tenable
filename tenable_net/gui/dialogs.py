"""Pull-from-Tenable and API-key settings dialogs."""

import html
import os
import re

from dotenv import load_dotenv
from PySide6.QtWidgets import (
    QCheckBox, QDialog, QDialogButtonBox, QFormLayout, QGroupBox, QHBoxLayout, QLabel, QLineEdit,
    QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QSpinBox, QTabWidget, QVBoxLayout, QWidget,
)

from tenable_net import akips, cisco, client, export, inventory
from tenable_net.gui.widgets import start_worker
from tenable_net.normalize import SEVERITY_ORDER


class PullDialog(QDialog):
    """Choose export filters, run the export in the background, and report progress."""

    def __init__(self, cache_dir, parent=None, client_factory=client.get_client,
                 akips_factory=None, cisco_factory=None):
        super().__init__(parent)
        # Factories return a client, or None when that source isn't configured.
        self.akips_factory = akips_factory or (lambda: akips.get_client() if akips.configured() else None)
        self.cisco_factory = cisco_factory or (lambda: cisco.get_client() if cisco.configured() else None)
        self.setWindowTitle("Pull from Tenable")
        self.setMinimumWidth(520)
        self.cache_dir = cache_dir
        self.client_factory = client_factory
        self.worker = None
        self.meta = None

        sev_box = QGroupBox("Severity")
        sev_row = QHBoxLayout(sev_box)
        self.sev_checks = {}
        for sev in SEVERITY_ORDER:
            cb = QCheckBox(sev.title())
            cb.setChecked(sev != "info")
            sev_row.addWidget(cb)
            self.sev_checks[sev] = cb

        state_box = QGroupBox("State")
        state_row = QHBoxLayout(state_box)
        self.state_checks = {}
        for state in ("open", "reopened", "fixed"):
            cb = QCheckBox(state.title())
            cb.setChecked(state != "fixed")
            state_row.addWidget(cb)
            self.state_checks[state] = cb

        form = QFormLayout()
        self.since = QSpinBox(minimum=0, maximum=3650, suffix=" days", specialValueText="Any time")
        self.since.setToolTip("Only findings seen within this many days (0 = no limit)")
        self.plugin_output = QCheckBox("Include plugin output (bigger, slower)")
        self.assets = QCheckBox("Also refresh the asset inventory")
        self.assets.setChecked(True)
        self.hardware = QCheckBox("Hardware inventory (AKiPS + Tenable plugin output)")
        self.hardware.setChecked(True)
        self.hardware.setToolTip("Model and serial per chassis/stack member. AKiPS is used when configured in Settings.")
        self.lifecycle = QCheckBox("Cisco lifecycle + contract (EoX, Serial Number to Info)")
        self.lifecycle.setChecked(cisco.configured())
        if not cisco.configured():
            self.lifecycle.setToolTip("Add Cisco API credentials in Settings to enable.")
        self.recheck = QCheckBox("Re-query Cisco even if results are cached (normally kept 7 days)")
        self.hardware.toggled.connect(lambda on: self.lifecycle.setEnabled(on))
        self.lifecycle.toggled.connect(lambda on: self.recheck.setEnabled(on))
        self.recheck.setEnabled(self.lifecycle.isChecked())
        self.warnings = 0
        form.addRow("Last seen within", self.since)
        form.addRow(self.plugin_output)
        form.addRow(self.assets)
        form.addRow(self.hardware)
        form.addRow(self.lifecycle)
        form.addRow(self.recheck)

        self.progress = QProgressBar()
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        self.status = QLabel("Ready.")
        self.log = QPlainTextEdit(readOnly=True)
        self.log.setMaximumHeight(120)

        self.buttons = QDialogButtonBox()
        self.start_button = self.buttons.addButton("Start pull", QDialogButtonBox.AcceptRole)
        self.cancel_button = self.buttons.addButton(QDialogButtonBox.Cancel)
        self.start_button.clicked.connect(self.start)
        self.cancel_button.clicked.connect(self.cancel)

        layout = QVBoxLayout(self)
        for w in (sev_box, state_box):
            layout.addWidget(w)
        layout.addLayout(form)
        layout.addWidget(self.progress)
        layout.addWidget(self.status)
        layout.addWidget(self.log)
        layout.addWidget(self.buttons)

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
        self.status.setText("Requesting export from Tenable… (large exports can take several minutes)")
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
        self.status.setText(f"<b>{done} Finished with {self.warnings} warning(s), see the log below.</b>")
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
    """One tab of the settings dialog: a form of .env fields plus a Test button run off-thread."""

    def __init__(self, fields, hint, test_fn, parent=None):
        super().__init__(parent)
        self.fields = {}
        self.test_fn = test_fn
        self.worker = None
        form = QFormLayout()
        for key, label, secret in fields:
            edit = QLineEdit(os.getenv(key) or "")
            if secret:
                edit.setEchoMode(QLineEdit.Password)
            self.fields[key] = edit
            form.addRow(label, edit)
        show = QCheckBox("Show secrets")
        show.toggled.connect(self._toggle_echo)
        form.addRow(show)
        self._secret_keys = [k for k, _l, secret in fields if secret]
        note = QLabel(hint)
        note.setWordWrap(True)
        note.setStyleSheet("color: palette(placeholder-text);")
        self.test_button = QPushButton("Test connection")
        self.test_button.clicked.connect(self.test)
        self.result = QLabel()
        self.result.setWordWrap(True)
        row = QHBoxLayout()
        row.addWidget(self.test_button)
        row.addWidget(self.result, 1)
        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(note)
        layout.addLayout(row)
        layout.addStretch(1)

    def _toggle_echo(self, show):
        for key in self._secret_keys:
            self.fields[key].setEchoMode(QLineEdit.Normal if show else QLineEdit.Password)

    def values(self):
        return {k: e.text().strip() for k, e in self.fields.items()}

    def test(self):
        values = self.values()
        self.test_button.setEnabled(False)
        self.result.setText("Connecting…")
        self.worker = start_worker(lambda _w: self.test_fn(values), self, on_done=self._ok, on_error=self._fail)

    def _ok(self, message):
        self.test_button.setEnabled(True)
        self.result.setText(f"<span style='color:#2e7d32'>{html.escape(message)}</span>")

    def _fail(self, message):
        self.test_button.setEnabled(True)
        first = message.split("\n\n")[0].splitlines()
        text = next((line for line in reversed(first) if line.strip()), message)
        text = re.sub(r"^\w+(Error|Exception): ", "", text)
        self.result.setText(f"<span style='color:#c62828'>{html.escape(text)}</span>")


def _test_tenable(v):
    details = client.get_client(v["TIO_ACCESS_KEY"], v["TIO_SECRET_KEY"]).session.details()
    return f"Connected as {details.get('username') or details.get('email') or 'OK'}"


def _test_akips(v):
    c = akips.get_client(v["AKIPS_URL"], v["AKIPS_USER"] or "api-ro", v["AKIPS_PASSWORD"])
    return f"Connected: {c.test():,} devices"


def _test_cisco(v, cache_dir=None):
    """Token + each API. Uses a real serial / model from the cached inventory when there is one."""
    c = cisco.get_client(v["CISCO_CLIENT_ID"], v["CISCO_CLIENT_SECRET"])
    serial = pid = None
    if cache_dir is not None:
        try:
            serial, pid = inventory.sample_cisco_keys(cache_dir)
        except Exception:  # noqa: BLE001 - the probe still works without inventory
            pass
    results = cisco.diagnose(c, serial=serial, pid=pid)
    text = " · ".join(f"{'✔' if ok else ('–' if ok is None else '✘')} {name}: {detail}" for name, ok, detail in results)
    if any(ok is False for _n, ok, _d in results):
        raise RuntimeError(text)
    return text


class SettingsDialog(QDialog):
    """Tenable, AKiPS and Cisco API credentials, each with a connection test. Saved to .env."""

    def __init__(self, parent=None, cache_dir=None):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setMinimumWidth(600)
        load_dotenv(client.env_path())
        self.pages = {
            "Tenable": _ServicePage(
                [("TIO_ACCESS_KEY", "Access key", True), ("TIO_SECRET_KEY", "Secret key", True)],
                "Generate keys in Tenable under <i>Settings → My Account → API Keys</i>.", _test_tenable),
            "AKiPS": _ServicePage(
                [("AKIPS_URL", "URL", False), ("AKIPS_USER", "API user", False), ("AKIPS_PASSWORD", "Password", True)],
                "Optional. A read-only API user (e.g. <code>api-ro</code>). Supplies model and serial for "
                "every chassis / stack member via ENTITY-MIB.", _test_akips),
            "Cisco": _ServicePage(
                [("CISCO_CLIENT_ID", "Client ID", False), ("CISCO_CLIENT_SECRET", "Client secret", True)],
                "Optional. Cisco Support API app credentials with EoX and Serial Number to Information access. "
                "Override endpoints with CISCO_TOKEN_URL / CISCO_API_BASE in .env if needed. The test checks the "
                "token, EoX and Serial Number to Info separately.",
                lambda v: _test_cisco(v, cache_dir)),
        }
        self.tabs = QTabWidget()
        for name, page in self.pages.items():
            self.tabs.addTab(page, name)
        where = QLabel(f"Saved to <code>{client.env_path()}</code>")
        where.setStyleSheet("color: palette(placeholder-text);")
        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.save)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addWidget(self.tabs)
        layout.addWidget(where)
        layout.addWidget(buttons)

    def save(self):
        values = {}
        for page in self.pages.values():
            values.update(page.values())
        tenable = (values["TIO_ACCESS_KEY"], values["TIO_SECRET_KEY"])
        if any(tenable) and not all(tenable):
            QMessageBox.warning(self, "Settings", "Enter both Tenable keys, or neither.")
            return
        client.save_env({k: v for k, v in values.items() if v})
        self.accept()
