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


def test_hidden_views_load_on_first_use(window):
    assert window.current_view() == "overview"
    assert {"findings", "devices", "remediation", "hardware"} <= set(window._pending)
    window.navigate("remediation")
    assert "remediation" not in window._pending and window.remediation_view.model.rowCount() > 0
    assert window.devices_tab.devices_proxy.rowCount() > 0  # attribute access loads it too
    assert "devices" not in window._pending


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


# ---- shell: no menu bar, command palette, filter chips, counts --------------------------------------

def test_no_menu_bar_commands_live_in_shortcuts_and_workspace_menu(window):
    from PySide6.QtWidgets import QMenuBar, QWidget

    assert window.findChild(QMenuBar) is None
    # (window.actions is the remediation plan, so ask Qt for the window's QActions directly)
    shortcuts = {a.shortcut().toString() for a in QWidget.actions(window)}
    assert {"Ctrl+K", "Ctrl+P", "F5", "Ctrl+E", "Ctrl+Shift+E", "F11", "Ctrl+,", "Ctrl+1", "Ctrl+7"} <= shortcuts
    texts = [a.text() for a in window.app_menu.actions()]
    assert "Pull from Tenable…" in texts and "Settings…" in texts and "Quit" in texts


def test_command_palette_mouse_and_keyboard(window):
    from PySide6.QtTest import QTest

    palette = window.command_palette
    window.open_palette()
    assert not palette.isHidden()
    rows = palette.model.rows
    assert rows[0].header and any(r.title == "Go to Findings" for r in rows)
    assert not any(r.group == "Devices" for r in rows)  # targets only appear once you type

    palette.input.setText("core-sw-01")
    hits = [r for r in palette.model.rows if not r.header]
    assert hits[0].title.startswith("Search findings for") and any(r.title == "core-sw-01" for r in hits)
    row = next(i for i, r in enumerate(palette.model.rows) if r.title == "core-sw-01")
    palette.activate(palette.model.index(row))
    QApplication.processEvents()
    assert palette.isHidden() and window.current_view() == "devices"
    assert window.devices_tab.devices_model.frame.iloc[
        window.devices_tab.devices_proxy.mapToSource(window.devices_tab.devices_view.currentIndex()).row()
    ]["hostname"] == "core-sw-01"

    window.open_palette()
    QTest.keyClicks(palette.input, "trends")
    QTest.keyClick(palette.input, Qt.Key_Down)  # past "Search findings for …" to the view
    assert palette.list.currentIndex().data(Qt.UserRole).title == "Go to Trends"
    QTest.keyClick(palette.input, Qt.Key_Return)
    QApplication.processEvents()
    assert window.current_view() == "trends"

    window.open_palette()
    QTest.keyClick(palette.input, Qt.Key_Escape)
    assert palette.isHidden()
    window.open_palette()
    QTest.keyClicks(palette.input, "snmp")  # Enter on the first row searches the findings
    QTest.keyClick(palette.input, Qt.Key_Return)
    QApplication.processEvents()
    assert window.current_view() == "findings" and window.findings_tab.search.text() == "snmp"


def test_findings_filter_chips_summarise_filters(window):
    tab = window.findings_tab
    assert tab.severity_chip.text() == "Severity" and not tab.severity_chip.property("active")
    assert tab.reset_button.isHidden()
    for sev in ("medium", "low", "info"):
        tab.sev_checks[sev].setChecked(False)
    assert tab.severity_chip.text() == "Severity: Critical, High" and tab.severity_chip.property("active")
    assert not tab.reset_button.isHidden()
    tab.state_checks["FIXED"].setChecked(False)
    assert tab.state_chip.text() == "State: Open, Reopened"
    tab.min_vpr.setValue(7)
    tab.apply_filters()
    assert tab.vpr_chip.text() == "VPR: ≥ 7"
    tab.reset_filters()
    assert tab.severity_chip.text() == "Severity" and tab.vpr_chip.text() == "VPR" and tab.reset_button.isHidden()
    assert tab.panel.proxy.rowCount() == 8


def test_sidebar_counts(window):
    from tenable_net.gui.app import COUNT_ROLE

    assert window.nav_items["findings"].data(COUNT_ROLE) == f"{len(window.findings):,}"
    assert window.nav_items["remediation"].data(COUNT_ROLE) == f"{len(window.actions):,}"
    assert window.nav_items["devices"].data(COUNT_ROLE) == "5"  # 4 with findings + 1 asset without
    assert not window.nav_items["hardware"].data(COUNT_ROLE)  # no inventory in this fixture


def test_window_minimum_width_follows_the_visible_view(window):
    window.navigate("overview")
    overview_min = window.minimumSizeHint().width()
    assert overview_min < 1000  # a wide view elsewhere doesn't stop the window shrinking
    window.navigate("findings")
    assert window.minimumSizeHint().width() >= overview_min


def test_theme_switch_keeps_data(window):
    try:
        window.set_theme("dark")
        assert theme.mode() == "dark" and window.theme_actions["dark"].isChecked()
        assert window.overview.cards["critical"].value.text() == "3"
        window.set_theme("light")
        assert theme.mode() == "light"
    finally:
        window.set_theme("system")


def test_bundled_inter_font_and_icons(app):
    from tenable_net.gui import icons

    assert (theme.FONT_DIR / "LICENSE.txt").exists() and len(list(theme.FONT_DIR.glob("Inter-*.otf"))) == 3
    assert "Inter" in theme.load_fonts()
    for name in icons.PATHS:
        image = icons.pixmap(name, "#000000", 16).toImage()
        assert any(image.pixelColor(x, y).alpha() for x in range(image.width()) for y in range(image.height())), name


def test_every_view_paints_without_errors(window, monkeypatch):
    """Delegates and custom widgets paint in Python; PySide only prints exceptions raised there, so collect
    them through sys.excepthook and fail on any."""
    import sys

    errors = []
    monkeypatch.setattr(sys, "excepthook", lambda *exc: errors.append(exc))
    window.resize(1280, 800)
    window.show()
    for key, *_rest in NAV:
        window.navigate(key)
        assert not window.grab().toImage().isNull()
    window.open_palette()
    window.command_palette.input.setText("core")
    window.grab()
    window.command_palette.close_palette()
    window.notify("Saved")
    window.grab()
    assert errors == []
