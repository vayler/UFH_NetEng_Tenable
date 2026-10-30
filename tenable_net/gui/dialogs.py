"""Pull-from-Tenable and API-key settings dialogs."""

from PySide6.QtWidgets import (
    QCheckBox, QDialog, QDialogButtonBox, QFormLayout, QGroupBox, QHBoxLayout, QLabel, QLineEdit,
    QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QSpinBox, QVBoxLayout,
)

from tenable_net import client, export
from tenable_net.gui.widgets import start_worker
from tenable_net.normalize import SEVERITY_ORDER


class PullDialog(QDialog):
    """Choose export filters, run the export in the background, and report progress."""

    def __init__(self, cache_dir, parent=None, client_factory=client.get_client):
        super().__init__(parent)
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
        form.addRow("Last seen within", self.since)
        form.addRow(self.plugin_output)
        form.addRow(self.assets)

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

    def start(self):
        opts = self.options()
        if not opts["severity"] or not opts["state"]:
            QMessageBox.warning(self, "Pull", "Pick at least one severity and one state.")
            return
        try:
            tio = self.client_factory()
        except client.MissingCredentials:
            QMessageBox.warning(self, "API keys needed", "Add your Tenable API keys in Settings first.")
            if SettingsDialog(self).exec() != QDialog.Accepted:
                return
            tio = self.client_factory()

        def job(worker):
            return export.pull(
                tio, cache_dir=self.cache_dir,
                log=worker.log.emit,
                progress=worker.progress.emit,
                cancelled=lambda: worker.cancel_requested,
                **opts,
            )

        for w in (self.start_button, *self.sev_checks.values(), *self.state_checks.values(),
                  self.since, self.plugin_output, self.assets):
            w.setEnabled(False)
        self.progress.setRange(0, 0)  # indeterminate: Tenable doesn't report a total up front
        self.status.setText("Requesting export from Tenable… (large exports can take several minutes)")
        self.worker = start_worker(job, self, on_done=self._done, on_error=self._error,
                                   on_log=self._log, on_progress=self._progress)

    def _log(self, message):
        self.log.appendPlainText(str(message))

    def _progress(self, stage, count):
        self.status.setText(f"Downloading {stage}: {count:,} records…")

    def _done(self, meta):
        self.meta = meta
        self.progress.setRange(0, 1)
        self.progress.setValue(1)
        self.status.setText(f"Done: {meta['vuln_count']:,} findings, {meta['asset_count']:,} assets.")
        self.accept()

    def _error(self, message):
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        if message.startswith("ExportCancelled"):
            self.status.setText("Cancelled. The previous cached data was kept.")
            self.reject()
            return
        self.status.setText("Pull failed.")
        self._log(message)
        for w in (self.start_button, *self.sev_checks.values(), *self.state_checks.values(),
                  self.since, self.plugin_output, self.assets):
            w.setEnabled(True)
        QMessageBox.critical(self, "Pull failed", message.split("\n\n")[0])

    def cancel(self):
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


class SettingsDialog(QDialog):
    """Enter, test, and save the Tenable API keys to .env."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Tenable API keys")
        self.setMinimumWidth(560)
        self.worker = None
        access, secret = client.saved_credentials()

        self.access = QLineEdit(access or "", echoMode=QLineEdit.Password)
        self.secret = QLineEdit(secret or "", echoMode=QLineEdit.Password)
        show = QCheckBox("Show keys")
        show.toggled.connect(self._toggle_echo)

        form = QFormLayout()
        form.addRow("Access key", self.access)
        form.addRow("Secret key", self.secret)
        form.addRow(show)
        hint = QLabel(f"Generate keys in Tenable under <i>Settings → My Account → API Keys</i>.<br>"
                      f"Saved to <code>{client.env_path()}</code>.")
        hint.setWordWrap(True)
        hint.setStyleSheet("color: palette(placeholder-text);")

        self.test_button = QPushButton("Test connection")
        self.test_button.clicked.connect(self.test)
        self.result = QLabel()
        self.result.setWordWrap(True)
        test_row = QHBoxLayout()
        test_row.addWidget(self.test_button)
        test_row.addWidget(self.result, 1)

        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.save)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(hint)
        layout.addLayout(test_row)
        layout.addWidget(buttons)

    def _toggle_echo(self, show):
        for field in (self.access, self.secret):
            field.setEchoMode(QLineEdit.Normal if show else QLineEdit.Password)

    def _keys(self):
        return self.access.text().strip(), self.secret.text().strip()

    def test(self):
        access, secret = self._keys()
        if not access or not secret:
            self.result.setText("Enter both keys first.")
            return
        self.test_button.setEnabled(False)
        self.result.setText("Connecting…")

        def job(_worker):
            details = client.get_client(access, secret).session.details()
            return details.get("username") or details.get("email") or "OK"

        self.worker = start_worker(job, self, on_done=self._tested, on_error=self._test_failed)

    def _tested(self, user):
        self.test_button.setEnabled(True)
        self.result.setText(f"<span style='color:#2e7d32'>✔ Connected as {user}</span>")

    def _test_failed(self, message):
        self.test_button.setEnabled(True)
        self.result.setText(f"<span style='color:#c62828'>✘ {message.splitlines()[0]}</span>")

    def save(self):
        access, secret = self._keys()
        if not access or not secret:
            QMessageBox.warning(self, "API keys", "Both keys are required.")
            return
        client.save_credentials(access, secret)
        self.accept()
