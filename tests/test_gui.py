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
