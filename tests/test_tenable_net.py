import json
import shutil
from pathlib import Path

import openpyxl
import pytest

from tenable_net import cli, export, normalize, reports, summaries

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def vulns():
    return json.loads((FIXTURES / "vulns_sample.json").read_text())


@pytest.fixture
def assets():
    return json.loads((FIXTURES / "assets_sample.json").read_text())


@pytest.fixture
def cache_dir(tmp_path):
    shutil.copy(FIXTURES / "vulns_sample.json", tmp_path / export.VULNS_FILE)
    shutil.copy(FIXTURES / "assets_sample.json", tmp_path / export.ASSETS_FILE)
    return tmp_path


def test_findings_frame_excludes_info_by_default(vulns):
    df = normalize.findings_frame(vulns)
    assert len(df) == 7
    assert "info" not in set(df["severity"].astype(str))
    assert len(normalize.findings_frame(vulns, include_info=True)) == 8


def test_findings_frame_sorted_most_severe_first(vulns):
    df = normalize.findings_frame(vulns)
    assert df.iloc[0]["severity"] == "critical"
    assert df.iloc[0]["vpr"] == 10.0
    assert df.iloc[-1]["severity"] == "low"


def test_finding_row_handles_sparse_record():
    row = normalize.finding_row({"asset": {"uuid": "x"}, "plugin": {}, "severity": "High"})
    assert row["hostname"] == "x"
    assert row["severity"] == "high"
    assert row["cves"] == ""


def test_vendor_of():
    assert normalize.vendor_of("Cisco IOS XE 17.6.1") == "Cisco"
    assert normalize.vendor_of("Palo Alto Networks PAN-OS 10.2.3") == "Palo Alto"
    assert normalize.vendor_of("Juniper Junos OS 21.4R3") == "Juniper"
    assert normalize.vendor_of("") == "Unknown"


def test_rollups(vulns):
    df = normalize.findings_frame(vulns)
    devices = reports.by_device(df)
    assert devices.iloc[0]["critical"] == 1
    assert set(devices["hostname"]) == {"core-sw-01", "core-sw-02", "edge-fw-01", "dist-rtr-01"}

    plugins = reports.by_plugin(df)
    top = plugins.iloc[0]
    assert top["plugin_id"] == 180001 and top["devices"] == 2

    cves = reports.by_cve(df).set_index("cve")
    assert cves.loc["CVE-2023-20198", "devices"] == 2
    assert "CVE-2024-11112" in cves.index

    sev = reports.severity_summary(df).set_index("severity")
    assert sev.loc["critical", "findings"] == 3
    assert sev.loc["critical", "devices"] == 3


def test_write_reports(vulns, assets, tmp_path):
    paths = reports.write_reports(
        normalize.findings_frame(vulns), normalize.assets_frame(assets), out_dir=tmp_path
    )
    names = {p.name for p in paths}
    assert {"findings.csv", "by_device.csv", "by_plugin.csv", "by_cve.csv", "tenable_report.xlsx"} <= names
    wb = openpyxl.load_workbook(tmp_path / "tenable_report.xlsx")
    assert wb.sheetnames == [
        "Severity Summary", "By Device", "By Plugin", "By CVE", "By Vendor-OS", "Findings", "Assets",
    ]
    assert wb["Findings"].max_row == 8  # header + 7 findings


def test_device_and_search(vulns):
    df = normalize.findings_frame(vulns)
    assert len(summaries.device(df, "core-sw-01")) == 2
    assert len(summaries.device(df, "10.0.1.1")) == 2
    assert summaries.search(df, "CVE-2023-20198")["hostname"].nunique() == 2
    assert len(summaries.search(df, "180002")) == 1
    assert len(summaries.search(df, "globalprotect")) == 1


@pytest.mark.parametrize("argv", [
    ["summary"],
    ["device", "core-sw"],
    ["search", "CVE-2024-3400"],
])
def test_cli_read_commands(cache_dir, argv):
    assert cli.main(["--cache-dir", str(cache_dir), *argv]) == 0


def test_cli_report(cache_dir, tmp_path):
    out = tmp_path / "out"
    assert cli.main(["--cache-dir", str(cache_dir), "report", "--out", str(out)]) == 0
    assert (out / "tenable_report.xlsx").exists()


def test_cli_missing_cache(tmp_path):
    assert cli.main(["--cache-dir", str(tmp_path / "nope"), "summary"]) == 1


def test_pull_requires_credentials(monkeypatch, tmp_path):
    monkeypatch.delenv("TIO_ACCESS_KEY", raising=False)
    monkeypatch.delenv("TIO_SECRET_KEY", raising=False)
    monkeypatch.chdir(tmp_path)  # no .env here
    assert cli.main(["--cache-dir", str(tmp_path), "pull"]) == 2
