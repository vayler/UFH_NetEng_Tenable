import json
import shutil
from pathlib import Path

import pandas as pd

from tenable_net import akips, cisco, export, inventory, normalize, remediation, risk

FIXTURES = Path(__file__).parent / "fixtures"
STAMP = "2026-10-30T00:00:00+00:00"


def scored_findings():
    f = normalize.findings_frame(json.loads((FIXTURES / "vulns_sample.json").read_text()))
    f["vendor"] = f["os"].map(normalize.vendor_of)
    return risk.add_finding_scores(f)


def test_plan_groups_os_config_and_ranks():
    actions, members = remediation.plan(scored_findings())
    types = set(actions["type"])
    assert {"OS upgrade", "Configuration"} <= types
    cisco_up = actions[actions["title"].str.contains("Cisco IOS XE")]
    # both IOS XE advisories on core-sw-01/02 grouped into one upgrade action (no inventory -> grouped by OS)
    assert cisco_up["devices"].iloc[0] == 2 and cisco_up["findings"].iloc[0] == 3
    cfg = actions[actions["type"] == "Configuration"]
    assert any("SSL Self-Signed Certificate" in t for t in cfg["title"])
    assert list(actions["rank"]) == list(range(1, len(actions) + 1))
    assert actions["priority"].is_monotonic_decreasing
    total = sum(len(g) for g in members.values())
    assert total == len(scored_findings().query("risk > 0"))  # every scored finding in exactly one action


def test_members_are_built_on_demand():
    actions, members = remediation.plan(scored_findings())
    assert set(members) == set(actions["id"]) and len(members) == len(actions)
    cfg = actions[actions["type"] == "Configuration"].iloc[0]
    group = members[cfg["id"]]
    assert members[cfg["id"]] is group  # built once, then cached
    assert group["plugin_id"].nunique() == 1 and group["hostname"].nunique() == cfg["devices"]
    assert members.get("XX999") is None
    items = remediation.action_items(cfg.to_dict(), group)
    assert len(items) == cfg["devices"] and items["risk"].is_monotonic_decreasing


def test_os_advisory_detection():
    assert remediation.is_os_advisory({"plugin_family": "CISCO", "plugin_name": "x"})
    assert remediation.is_os_advisory({"plugin_family": "Junos Local Security Checks", "plugin_name": "x"})
    assert remediation.is_os_advisory({"plugin_family": "General", "plugin_name": "Palo Alto Networks PAN-OS 10.2 Vuln"})
    assert not remediation.is_os_advisory({"plugin_family": "General", "plugin_name": "SSL Self-Signed Certificate"})


def test_confidence_from_fixed_release_and_suggestion(tmp_path):
    f = scored_findings()
    f.loc[f["plugin_id"] == 180001, "output"] = "Installed version : 17.6.1\nFixed version     : 17.9.4a\n"
    f.loc[f["plugin_id"] == 180002, "output"] = "Fixed release: 17.12.1"
    inv = pd.DataFrame([{"hostname": h, "in_tenable": True, "akips_device": h, "ip": "", "vendor": "Cisco",
                         "member": 1, "model": "C9300-48P", "serial": "S", "sw_version": "17.6.1", "source": "AKiPS",
                         "recommended_sw": "17.9.5, 17.12.4", "contract": "Covered", "lifecycle": "", "ldos": pd.NaT}
                        for h in ("core-sw-01", "core-sw-02")])
    actions, _members = remediation.plan(f, inv)
    up = actions[actions["type"] == "OS upgrade"].set_index("title")
    title = next(t for t in up.index if "C9300-48P" in t)
    assert "to 17.12.4" in title and up.loc[title, "confidence"] == "Confirmed"
    f.loc[f["plugin_id"] == 180002, "output"] = "Fixed release: 17.15.1"
    actions, _ = remediation.plan(f, inv)
    assert actions.loc[actions["title"].str.contains("C9300-48P"), "confidence"].item() == "Check"


def test_hardware_actions_and_items(tmp_path):
    f = scored_findings()
    inv = pd.DataFrame([{"hostname": "core-sw-01", "in_tenable": True, "akips_device": "", "ip": "", "vendor": "Cisco",
                         "member": 1, "model": "C9300-48P", "serial": "S", "sw_version": "", "source": "",
                         "recommended_sw": None, "contract": "Not covered", "lifecycle": "Past LDoS", "ldos": pd.NaT}])
    actions, members = remediation.plan(f, inv)
    hw = actions[actions["type"] == "Hardware"]
    assert {t.split(" (")[0] for t in hw["title"]} == {"Renew support contract",
                                                       "Replace hardware past Last Date of Support"}
    a = actions.iloc[0].to_dict()
    items = remediation.action_items(a, members[a["id"]])
    assert "hostname" in items and items["risk"].is_monotonic_decreasing


def test_cli_remediation_and_report_sheet(tmp_path, monkeypatch):
    import openpyxl

    from tenable_net import cli

    monkeypatch.chdir(tmp_path)
    shutil.copy(FIXTURES / "vulns_sample.json", tmp_path / export.VULNS_FILE)
    shutil.copy(FIXTURES / "assets_sample.json", tmp_path / export.ASSETS_FILE)
    assert cli.main(["--cache-dir", str(tmp_path), "remediation"]) == 0
    assert cli.main(["--cache-dir", str(tmp_path), "report", "--out", str(tmp_path / "out")]) == 0
    wb = openpyxl.load_workbook(tmp_path / "out" / "tenable_report.xlsx")
    assert {"Remediation", "Remediation devices"} <= set(wb.sheetnames)
