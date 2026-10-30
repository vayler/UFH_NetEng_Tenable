"""Theme, glossary and the app shell (header, navigation, global search)."""

import json
import os
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6.QtWidgets", exc_type=ImportError)

from PySide6.QtCore import QSettings, Qt  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from tenable_net import export, glossary  # noqa: E402
from tenable_net.gui import theme  # noqa: E402
from tenable_net.gui.app import NAV, MainWindow  # noqa: E402
from tenable_net.gui.models import DataFrameModel  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def app():
    QSettings.setDefaultFormat(QSettings.IniFormat)
    return QApplication.instance() or QApplication([])


@pytest.fixture
def window(app, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    shutil.copy(FIXTURES / "vulns_sample.json", tmp_path / export.VULNS_FILE)
    shutil.copy(FIXTURES / "assets_sample.json", tmp_path / export.ASSETS_FILE)
    w = MainWindow(tmp_path)
    yield w
    w.close()


@pytest.mark.parametrize("mode", ["light", "dark"])
def test_theme_contrast_meets_wcag_aa(mode):
    failures = [(name, round(theme.contrast(fg, bg), 2)) for name, fg, bg in theme.text_pairs(mode)
                if theme.contrast(fg, bg) < 4.5]
    assert failures == []


def test_severity_palette_distinct_from_brand():
    assert theme.SEVERITY_COLORS["high"].lower() != theme.BRAND["orange"].lower()
    assert theme.SEVERITY_COLORS["low"].lower() != theme.BRAND["blue"].lower()


def test_glossary_covers_visible_columns():
    from tenable_net.gui.devices import DEVICE_FINDING_COLUMNS, HARDWARE_DEVICE_COLUMNS
    from tenable_net.gui.findings import FINDING_TABLE_COLUMNS

    explained = {"severity", "vpr", "cvss3", "cves", "plugin_id", "exploit_available", "state", "last_found",
                 "contract", "sw_status", "lifecycle", "model"}
    shown = set(FINDING_TABLE_COLUMNS) | set(DEVICE_FINDING_COLUMNS) | set(HARDWARE_DEVICE_COLUMNS)
    for col in explained & shown:
        assert glossary.tooltip(col), col
    assert all(term in glossary.TERMS for term in glossary.COLUMNS.values())


def test_header_tooltips_come_from_glossary(app):
    import pandas as pd

    model = DataFrameModel(pd.DataFrame({"vpr": [9.8]}))
    assert "Vulnerability Priority Rating" in model.headerData(0, Qt.Horizontal, Qt.ToolTipRole)


def test_theme_apply_switches_palette(app):
    assert theme.apply(app, "dark") == "dark"
    assert app.palette().color(app.palette().ColorRole.Window).name().lower() == theme.TOKENS["dark"]["bg"].lower()
    assert theme.apply(app, "light") == "light"


def test_navigation_and_navigate(window):
    for key, *_rest in NAV:
        page = window.navigate(key)
        assert window.current_view() == key and window.pages.currentWidget() is page
        assert window.page_title.text()  # top bar shows the page title
        assert window.nav.currentItem().data(Qt.UserRole) == key
    window.navigate("findings", severity="critical")
    assert window.findings_tab.panel.proxy.rowCount() == 3
    window.navigate("devices", hostname="dist-rtr-01")
    assert window.devices_tab.panel.proxy.rowCount() == 3
    # clicking a sidebar row switches view
    window.nav.setCurrentRow(1)
    assert window.current_view() == "findings"


def test_global_search_targets(window):
    keys = window.search_targets
    assert "Device · core-sw-01" in keys and "CVE · CVE-2024-3400" in keys
    assert any(k.startswith("Plugin · 180001") for k in keys)
    window._search_activated("CVE · CVE-2023-20198")
    assert window.current_view() == "findings" and window.findings_tab.panel.proxy.rowCount() == 2
    window._search_activated("Device · edge-fw-01")
    assert window.current_view() == "devices"
    window._search_activated("snmp")  # free text -> findings search
    assert window.findings_tab.search.text() == "snmp"


def test_freshness_chip(window):
    window.meta = {"pulled_at": (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat()}
    window._update_header()
    assert window.fresh_chip.plain_text == "Pulled 3 h ago" and window.fresh_chip.status == "good"
    window.meta = {"pulled_at": (datetime.now(timezone.utc) - timedelta(days=9)).isoformat()}
    window._update_header()
    assert window.fresh_chip.plain_text == "Pulled 9 days ago" and window.fresh_chip.status == "bad"


def test_empty_state_checklist(app, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    w = MainWindow(tmp_path / "nothing")
    assert w.stack.currentIndex() == 0
    assert "Pull findings from Tenable" in w.checklist.text()
    assert not w.report_button.isEnabled()
    w.close()


def test_cache_change_reloads(window, tmp_path):
    vulns = json.loads((tmp_path / export.VULNS_FILE).read_text())
    export.save_cache(vulns[:2], [], {"severity": ["critical"]}, tmp_path)  # e.g. a CLI pull
    window._cache_changed()
    assert len(window.findings) == 2


def test_history_in_the_ui(app, tmp_path, monkeypatch):
    import pandas as pd

    from tenable_net import history, normalize

    monkeypatch.chdir(tmp_path)
    vulns = json.loads((FIXTURES / "vulns_sample.json").read_text())
    f = normalize.findings_frame(vulns)
    history.save(tmp_path, history.build_snapshot(f[f["plugin_id"] != 180002], "2026-10-01T00:00:00+00:00"))
    export.save_cache(vulns, [], {}, tmp_path)
    history.record(tmp_path)  # the "current" pull
    w = MainWindow(tmp_path)
    assert w.overview.change_stats["new"][0].text() == "1"
    assert "▲" in w.overview.cards["high"].delta.text()
    w.navigate("findings", changed=True)
    assert w.findings_tab.panel.proxy.rowCount() == 1
    trends = w.navigate("trends")
    assert w.current_view() == "trends" and "2 pulls" in trends.summary.text()
    w.close()


def test_remediation_view(window):
    view = window.navigate("remediation")
    assert view.proxy.rowCount() == len(window.actions) > 0
    frame = view.model.frame
    first = frame.iloc[view.proxy.source_row(0)]
    assert first["rank"] == 1  # rank order kept
    view.type_filter.setCurrentText("Configuration")
    assert all(frame.iloc[view.proxy.source_row(r)]["type"] == "Configuration" for r in range(view.proxy.rowCount()))
    action_id = window.actions.iloc[1]["id"]
    window.overview.action_activated.emit(action_id)
    assert window.current_view() == "remediation" and view.current_action()["id"] == action_id
    assert view.items_model.rowCount() > 0
