import json
import os
import shutil
import time
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6.QtWidgets", exc_type=ImportError)

from PySide6.QtCore import QSettings  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from tenable_net import export, inventory, normalize  # noqa: E402
from tenable_net.gui.app import MainWindow  # noqa: E402
from tenable_net.gui.dialogs import PullDialog  # noqa: E402
from tenable_net.gui.filters import filter_mask  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def app():
    QSettings.setDefaultFormat(QSettings.IniFormat)
    return QApplication.instance() or QApplication([])


@pytest.fixture
def cache_dir(tmp_path):
    shutil.copy(FIXTURES / "vulns_sample.json", tmp_path / export.VULNS_FILE)
    shutil.copy(FIXTURES / "assets_sample.json", tmp_path / export.ASSETS_FILE)
    return tmp_path


@pytest.fixture
def window(app, cache_dir):
    w = MainWindow(cache_dir)
    yield w
    w.close()


def wait_until(app, condition, timeout=10):
    end = time.time() + timeout
    while not condition() and time.time() < end:
        app.processEvents()
        time.sleep(0.01)
    assert condition()


def test_filter_mask():
    df = normalize.findings_frame(json.loads((FIXTURES / "vulns_sample.json").read_text()), include_info=True)
    df["vendor"] = df["os"].map(normalize.vendor_of)
    assert filter_mask(df).sum() == 8
    assert filter_mask(df, severities=["critical"]).sum() == 3
    assert filter_mask(df, exploitable_only=True).sum() == 3
    assert filter_mask(df, states=["reopened"]).sum() == 1
    assert filter_mask(df, vendor="Juniper").sum() == 3
    assert filter_mask(df, min_vpr=9.9).sum() == 1
    assert filter_mask(df, text="cve-2023-20198").sum() == 2
    assert filter_mask(df, text="180002").sum() == 1
    assert filter_mask(df, text="core-sw snmp").sum() == 1  # every term must match


def test_window_loads_cache(window):
    assert window.stack.currentIndex() == 1
    assert window.findings_tab.panel.proxy.rowCount() == 8
    assert window.overview.cards["critical"].value.text() == "3"
    assert window.overview.devices_model.rowCount() == 4
    # devices list = 4 with findings + 1 asset with none
    assert window.devices_tab.devices_proxy.rowCount() == 5


def test_findings_filters_and_drilldown(window):
    tab = window.findings_tab
    tab.sev_checks["info"].setChecked(False)
    assert tab.panel.proxy.rowCount() == 7
    tab.exploitable.setChecked(True)
    assert tab.panel.proxy.rowCount() == 3
    tab.reset_filters()
    assert tab.panel.proxy.rowCount() == 8

    window.open_plugin("180001")
    assert tab.panel.proxy.rowCount() == 2
    window.open_severity("high")
    assert tab.panel.proxy.rowCount() == 2
    assert all(tab.panel.proxy.index(r, 0).data() == "high" for r in range(2))
    assert "Junos J-Web RCE" in tab.panel.detail.toPlainText()  # highest-VPR high finding selected


def test_device_drilldown(window):
    assert window.devices_tab.select_device("dist-rtr-01")
    assert window.devices_tab.panel.proxy.rowCount() == 3
    assert "dist-rtr-01" in window.devices_tab.header.text()
    assert window.devices_tab.select_device("oob-sw-09")  # asset without findings
    assert window.devices_tab.panel.proxy.rowCount() == 0


def test_empty_state(app, tmp_path):
    w = MainWindow(tmp_path / "missing")
    assert w.stack.currentIndex() == 0
    assert not w.report_action.isEnabled()
    w.close()


class FakeExports:
    def __init__(self, vulns, assets):
        self._vulns, self._assets = vulns, assets
        self.vuln_calls = []

    @property
    def vuln_kwargs(self):
        return self.vuln_calls[0]

    def vulns(self, **kwargs):
        self.vuln_calls.append(kwargs)
        if kwargs.get("plugin_id"):  # hardware inventory export
            return iter(json.loads((FIXTURES / "tenable_inventory_sample.json").read_text()))
        return iter(self._vulns)

    def assets(self, **kwargs):
        return iter(self._assets)


class FakeTio:
    def __init__(self):
        self.exports = FakeExports(
            json.loads((FIXTURES / "vulns_sample.json").read_text()),
            json.loads((FIXTURES / "assets_sample.json").read_text()),
        )


def test_pull_dialog_writes_cache(app, tmp_path):
    tio = FakeTio()
    dialog = PullDialog(tmp_path, client_factory=lambda: tio, akips_factory=lambda: None, cisco_factory=lambda: None)
    dialog.sev_checks["low"].setChecked(False)
    dialog.since.setValue(30)
    dialog.start()
    wait_until(app, lambda: dialog.meta is not None)
    assert dialog.meta["vuln_count"] == 8 and dialog.meta["asset_count"] == 2
    assert tio.exports.vuln_kwargs["severity"] == ["critical", "high", "medium"]
    assert tio.exports.vuln_kwargs["state"] == ["OPEN", "REOPENED"]
    assert "last_found" in tio.exports.vuln_kwargs
    vulns, assets, meta = export.load_cache(tmp_path)
    assert len(vulns) == 8 and meta["filters"]["since_days"] == 30
    # hardware inventory ran as a second, plugin-filtered export
    assert tio.exports.vuln_calls[1]["plugin_id"] == [67217, 47864]
    assert set(inventory.load_inventory(tmp_path)["hostname"]) >= {"core-sw-02", "old-sw-07"}
    dialog.worker.thread.wait(2000)


def test_pull_dialog_hardware_off(app, tmp_path):
    tio = FakeTio()
    dialog = PullDialog(tmp_path, client_factory=lambda: tio, akips_factory=lambda: None, cisco_factory=lambda: None)
    dialog.hardware.setChecked(False)
    assert not dialog.lifecycle.isEnabled()
    dialog.start()
    wait_until(app, lambda: dialog.meta is not None)
    assert len(tio.exports.vuln_calls) == 1
    dialog.worker.thread.wait(2000)


def test_export_cancel(app, tmp_path, monkeypatch):
    monkeypatch.setattr(export, "PROGRESS_EVERY", 1)
    with pytest.raises(export.ExportCancelled):
        export.pull(FakeTio(), ["high"], ["open"], cache_dir=tmp_path, cancelled=lambda: True)
    assert not (tmp_path / export.VULNS_FILE).exists()


# ---- hardware inventory in the GUI ------------------------------------------------

@pytest.fixture
def inventory_cache(cache_dir):
    from tenable_net import akips, cisco

    fx = lambda name: json.loads((FIXTURES / name).read_text())  # noqa: E731
    inventory._write(cache_dir, inventory.AKIPS_FILE, akips.rows_from_raw(fx("akips_raw_sample.json")))
    inventory._write(cache_dir, inventory.TENABLE_FILE,
                     inventory.parse_tenable_inventory(fx("tenable_inventory_sample.json")))
    stamp = "2026-10-30T00:00:00+00:00"
    cisco.save_cache(cache_dir, {
        "coverage": {k: {**v, "fetched_at": stamp} for k, v in cisco.parse_coverage(fx("cisco_coverage_sample.json")).items()},
        "eox_serial": {k: {**v, "fetched_at": stamp} for k, v in cisco.parse_eox(fx("cisco_eox_sample.json")).items()},
        "eox_pid": {},
    })
    return cache_dir


def test_devices_tab_hardware(app, inventory_cache):
    w = MainWindow(inventory_cache)
    tab = w.devices_tab
    assert "model" in tab.devices_model.columns and "lifecycle" in tab.devices_model.columns
    assert tab.lifecycle_filter.isVisibleTo(tab)
    # 5 Tenable devices + AKiPS-only lab-sw-01 + Tenable-inventory-only old-sw-07
    assert tab.devices_proxy.rowCount() == 7

    tab.lifecycle_filter.setCurrentText("Past last day of support")
    assert tab.devices_proxy.rowCount() == 1
    tab.lifecycle_filter.setCurrentText("Not under contract")
    assert tab.devices_proxy.rowCount() == 2
    tab.lifecycle_filter.setCurrentText("In AKiPS but not in Tenable")
    assert tab.devices_proxy.rowCount() == 1
    tab.lifecycle_filter.setCurrentText("All devices")

    tab.search.setText("FOC2401X0BB")  # search by serial
    assert tab.devices_proxy.rowCount() == 1
    assert tab.select_device("core-sw-01")
    header = tab.header.text()
    assert "FOC2401X0AA" in header and "FOC2401X0BB" in header and "Not covered" in header
    assert tab.select_device("lab-sw-01")
    assert "Not in Tenable" in tab.header.text() and "EoL bulletin" in tab.header.text()

    assert w.overview.cards["hardware"].isVisibleTo(w.overview)
    w.close()


def test_hardware_card_hidden_without_inventory(window):
    assert not window.overview.cards["hardware"].isVisibleTo(window.overview)
    assert not window.devices_tab.lifecycle_filter.isVisibleTo(window.devices_tab)


def test_crash_handler_logs_and_reports(app, tmp_path, monkeypatch):
    import sys

    from tenable_net.gui import app as app_module

    shown = []
    monkeypatch.setattr(app_module.QMessageBox, "critical", lambda *a: shown.append(a))
    monkeypatch.setattr(sys, "excepthook", sys.excepthook)  # restored after the test
    log = tmp_path / "logs" / "gui-error.log"
    hook = app_module.install_crash_handler(log)
    try:
        raise ValueError("boom")
    except ValueError:
        hook(*sys.exc_info())
    assert "ValueError: boom" in log.read_text()
    assert shown and "boom" in shown[0][2]


def test_pull_dialog_stays_open_on_warnings(app, tmp_path):
    from tenable_net import cisco

    class FailingCisco:
        def coverage(self, serials):
            raise cisco.CiscoApiError("HTTP 403 (this API isn't enabled)")

        eox_by_serial = eox_by_pid = coverage

    tio = FakeTio()
    dialog = PullDialog(tmp_path, client_factory=lambda: tio, akips_factory=lambda: None,
                        cisco_factory=lambda: FailingCisco())
    dialog.lifecycle.setChecked(True)
    dialog.start()
    wait_until(app, lambda: dialog.meta is not None)
    dialog.worker.thread.wait(2000)
    assert dialog.warnings >= 1 and dialog.result() == 0  # still open
    assert "403" in dialog.log.toPlainText()
    assert dialog.cancel_button.text() == "Close"
    dialog.cancel()  # Close keeps the pulled data
    assert dialog.result() == 1


def test_software_suggestion_in_devices_tab(app, inventory_cache):
    from tenable_net import cisco

    cache = cisco.load_cache(inventory_cache)
    cache["software"] = {"C9300-48P": {"releases": [{"release": "17.12.4", "suggested": True,
                                                       "software_type": "IOS XE Software"}],
                                        "fetched_at": "2026-10-30T00:00:00+00:00"}}
    cisco.save_cache(inventory_cache, cache)
    w = MainWindow(inventory_cache)
    tab = w.devices_tab
    assert "sw_status" in tab.devices_model.columns
    tab.lifecycle_filter.setCurrentText("Software upgrade suggested")
    assert tab.devices_proxy.rowCount() == 1  # core-sw-01 runs 17.09.04a < 17.12.4
    assert tab.select_device("core-sw-01")
    assert "17.12.4" in tab.header.text() and "Upgrade suggested" in tab.header.text()
    w.close()


def test_settings_cisco_api_choices(app, tmp_path, monkeypatch):
    from tenable_net.gui.dialogs import SettingsDialog

    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("CISCO_APIS", raising=False)
    dialog = SettingsDialog()
    page = dialog.pages["Cisco"]
    assert {k for k, cb in page.choice_checks.items() if cb.isChecked()} == {"sn2info", "software"}
    # a Test connection result ticks what answered and unticks what was refused
    page._ok({"html": "x", "apis": {"sn2info": True, "software": True, "eox": False}})
    page.choice_checks["eox"].setChecked(True)
    page._ok({"html": "x", "apis": {"eox": False}})
    assert not page.choice_checks["eox"].isChecked()
    page.choice_checks["software"].setChecked(False)
    dialog.save()
    assert "CISCO_APIS=sn2info" in (tmp_path / ".env").read_text()


def test_diagnostics_window(app, inventory_cache, monkeypatch, tmp_path):
    from tenable_net import akips, cisco
    from tenable_net.gui import diagnostics_window as dw

    monkeypatch.chdir(inventory_cache)
    monkeypatch.delenv("CISCO_APIS", raising=False)
    for key in ("CISCO_CLIENT_ID", "CISCO_CLIENT_SECRET", "AKIPS_URL"):  # buttons need configured services
        monkeypatch.setenv(key, "test")
    w = MainWindow(inventory_cache)
    w.open_diagnostics()
    win = w.diagnostics_window
    assert win.isVisible()
    stages = list(win.stage_model.frame["stage"])
    assert stages[0] == "All devices" and "Not matched to AKiPS" in stages

    # clicking a stage filters the device list and shows the hint
    row = stages.index("Not matched to AKiPS")
    win.stage_view.selectRow(row)
    assert win.device_proxy.rowCount() == 2
    assert "device_aliases.csv" in win.hint.text()
    assert "Not matched" in win.detail.toPlainText()
    win.stage_view.selectRow(0)
    assert win.device_proxy.rowCount() == len(win.devices)
    win.search.setText("core-sw-01")
    assert win.device_proxy.rowCount() == 1

    # raw AKiPS dump and per-device Cisco re-query run on the worker thread
    class FakeAkips:
        def device_dump(self, device):
            return f"{device} 1000 ENTITY-MIB.entPhysicalSerialNum = FOC2401X0AA\n{device} sys ip4addr = 10.0.0.1\n"

    monkeypatch.setattr(akips, "get_client", lambda *a, **k: FakeAkips())
    win.show_raw()
    wait_until(app, lambda: "look relevant" in win.raw.toPlainText())
    assert "entPhysicalSerialNum" in win.raw.toPlainText()

    calls = []

    class FakeCisco:
        item_errors = {}

        def coverage(self, serials):
            calls.append(serials)
            return {s: {"covered": True} for s in serials}

        def software(self, pids):
            return {p: {"releases": [{"release": "17.12.4", "suggested": True}]} for p in pids}

    monkeypatch.setattr(cisco, "get_client", lambda *a, **k: FakeCisco())
    win.requery()
    wait_until(app, lambda: calls and win.requery_button.isEnabled())
    assert sorted(calls[0]) == ["FOC2401X0AA", "FOC2401X0BB"]

    monkeypatch.setattr(dw.QFileDialog, "getSaveFileName", lambda *a, **k: (str(tmp_path / "d.csv"), ""))
    win.export_csv()
    assert (tmp_path / "d.csv").read_text().startswith("hostname")
    win.close()
    w.close()


def test_devices_header_shows_enrichment_reason(app, inventory_cache, monkeypatch):
    monkeypatch.chdir(inventory_cache)
    w = MainWindow(inventory_cache)
    assert w.devices_tab.select_device("core-sw-02")
    assert "Enrichment:" in w.devices_tab.header.text()
    w.close()
