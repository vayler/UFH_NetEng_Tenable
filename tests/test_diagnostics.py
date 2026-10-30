"""Coverage fixes (devices that used to drop out of enrichment) and the diagnostics report."""

import json
import shutil
import zipfile
from pathlib import Path

import pytest

from tenable_net import akips, cisco, diagnostics, export, inventory

FIXTURES = Path(__file__).parent / "fixtures"
STAMP = "2026-10-30T00:00:00+00:00"


def ent(device, child, attr, value):
    return (device, child, f"ENTITY-MIB.entPhysical{attr}", value)


# ---- 1/2: AKiPS chassis detection ---------------------------------------------------

def test_classes_without_chassis_use_contained_in():
    lines = [ent("r1", "1", "Class", "other"), ent("r1", "1", "ContainedIn", "0"),
             ent("r1", "1", "ModelName", "ISR4331/K9"), ent("r1", "1", "SerialNum", "FDO2001A0AA"),
             ent("r1", "5", "Class", "module"), ent("r1", "5", "ContainedIn", "1"),
             ent("r1", "5", "ModelName", "NIM-ES2-4"), ent("r1", "5", "SerialNum", "FOC1111"),
             # a stack whose members aren't classed as chassis
             ent("s1", "1", "Class", "stack"), ent("s1", "1", "ContainedIn", "0"),
             ent("s1", "1000", "Class", "other"), ent("s1", "1000", "ContainedIn", "1"),
             ent("s1", "1000", "ModelName", "C9300-48P"), ent("s1", "1000", "SerialNum", "FOC2401X0AA"),
             ent("s1", "2000", "Class", "other"), ent("s1", "2000", "ContainedIn", "1"),
             ent("s1", "2000", "ModelName", "C9300-48P"), ent("s1", "2000", "SerialNum", "FOC2401X0BB")]
    rows, devices = akips.parse_inventory([], lines)
    by = {}
    for r in rows:
        by.setdefault(r["akips_device"], []).append(r["serial"])
    assert by == {"r1": ["FDO2001A0AA"], "s1": ["FOC2401X0AA", "FOC2401X0BB"]}
    rules = {d["akips_device"]: d["chassis_rule"] for d in devices}
    assert rules == {"r1": "top-level (containedIn)", "s1": "top-level (containedIn)"}


def test_classes_without_chassis_or_contained_in_fall_back():
    lines = [ent("r2", "3", "Class", "module"), ent("r2", "3", "ModelName", "WS-C2960X-48FPD-L"),
             ent("r2", "3", "SerialNum", "FOC1950W0EE"), ent("r2", "9", "Class", "port")]
    rows, devices = akips.parse_inventory([], lines)
    assert [r["serial"] for r in rows] == ["FOC1950W0EE"]
    assert devices[0]["chassis_rule"] == "first entity with serial/model"


def test_device_level_serial_without_entity_rows():
    sys_lines = [("old1", "sys", "SNMPv2-MIB.sysDescr", "Cisco IOS Software, C3560"),
                 ("old1", "sys", "OLD-CISCO-CHASSIS-MIB.chassisId", "FOC0909X1AB"),
                 ("bare", "sys", "SNMPv2-MIB.sysDescr", "Cisco IOS Software")]
    rows, devices = akips.parse_inventory(sys_lines, [])
    assert [(r["akips_device"], r["serial"]) for r in rows] == [("old1", "FOC0909X1AB")]
    issues = {d["akips_device"]: d["issue"] for d in devices}
    assert issues["old1"] == "" and "no ENTITY-MIB" in issues["bare"]


def test_device_diagnostics_record_issues():
    lines = [ent("n1", "1", "Class", "chassis"), ent("n1", "1", "ModelName", "N9K-C93180YC-EX"),
             ent("n1", "1", "SerialNum", "")]
    _rows, devices = akips.parse_inventory([("n1", "sys", "SNMPv2-MIB.sysName", "n1.example.edu")], lines)
    assert devices[0]["issue"] == "AKiPS returned no serial number"
    assert devices[0]["sys_name"] == "n1.example.edu" and devices[0]["with_model"] == 1


# ---- 3/4: matching and merge --------------------------------------------------------

@pytest.fixture
def device_index():
    return inventory.tenable_device_index(json.loads((FIXTURES / "vulns_sample.json").read_text()),
                                          json.loads((FIXTURES / "assets_sample.json").read_text()))


def akips_row(device, ip=None, sys_name=None, serial="X1", model="C9300-48P", member=1, sys_descr="Cisco IOS"):
    return {"akips_device": device, "ip": ip, "sys_name": sys_name, "sys_descr": sys_descr, "member": member,
            "model": model, "serial": serial, "sw_version": ""}


def test_match_by_sysname_when_ip_and_name_differ(device_index):
    inv = inventory.build_inventory([akips_row("AKIPS-CORE1", ip="192.0.2.50", sys_name="core-sw-01.net.example.edu")],
                                    [], device_index)
    assert inv["hostname"].item() == "core-sw-01" and inv["match_method"].item() == "sysName"


def test_match_by_alias(device_index, tmp_path):
    (tmp_path / "device_aliases.csv").write_text("akips_device,tenable_hostname\n# comment\nmystery-box,10.0.2.1\n")
    aliases = inventory.load_aliases(tmp_path / "device_aliases.csv")
    inv = inventory.build_inventory([akips_row("Mystery-Box", ip="192.0.2.99")], [], device_index, aliases)
    assert inv["hostname"].item() == "dist-rtr-01" and inv["match_method"].item() == "alias"


def test_tenable_serial_fills_blank_akips_serial(device_index):
    tenable = [{"asset_uuid": "u", "hostname": "core-sw-01", "ip": "10.0.0.1", "member": 1, "plugin_id": 67217,
                "model": "C9300-48P", "serial": "FOC9999Z1ZZ", "sw_version": "17.9.4a"}]
    inv = inventory.build_inventory([akips_row("core-sw-01", ip="10.0.0.1", serial="")], tenable, device_index)
    row = inv.iloc[0]
    assert row["serial"] == "FOC9999Z1ZZ" and row["sw_version"] == "17.9.4a"
    assert row["source"].startswith("AKiPS + Tenable 67217")


def test_cisco_model_beats_generic_linux(device_index):
    for model in ("SNS-3655-K9", "UCSC-C220-M5SX"):  # ISE appliance, UCS server
        inv = inventory.build_inventory([akips_row("box", ip="192.0.2.7", model=model,
                                                   sys_descr="Linux box 4.18.0")], [], device_index)
        assert inv["vendor"].item() == "Cisco" and inv["vendor_source"].item() == "model number"
    inv = inventory.build_inventory([akips_row("srv", ip="192.0.2.9", model="PowerEdge R640",
                                               sys_descr="Linux srv")], [], device_index)
    assert inv["vendor"].item() == "Linux"


# ---- 6/7: Cisco requests ----------------------------------------------------------------

class Resp:
    def __init__(self, status, body=None):
        self.status_code, self._body, self.headers, self.text = status, body or {}, {}, json.dumps(body or {})

    def json(self):
        return self._body

    def raise_for_status(self):
        pass


class RoutingSession:
    """Fake Cisco: a request containing BAD-SN gets HTTP 400; others return covered records."""

    def __init__(self, pages=1):
        self.urls, self.pages = [], pages

    def post(self, url, data=None, timeout=None):
        return Resp(200, {"access_token": "t", "expires_in": 3600})

    def get(self, url, headers=None, timeout=None):
        self.urls.append(url)
        path, _, query = url.partition("?")
        serials = path.rsplit("/", 1)[1].split(",")
        if "BAD-SN" in serials:
            return Resp(400, {"error": "invalid serial"})
        page = int(query.split("=")[1]) if "=" in query else 1
        half = serials[(page - 1)::self.pages]
        return Resp(200, {"pagination_response_record": {"page_index": page, "last_index": self.pages},
                          "serial_numbers": [{"sr_no": s, "is_covered": "YES"} for s in half]})


def test_one_bad_serial_only_loses_itself():
    session = RoutingSession()
    client = cisco.CiscoClient("id", "secret", session=session)
    serials = [f"FOC{i:08d}" for i in range(74)] + ["BAD-SN"]
    out = client.coverage(serials)
    assert len(out) == 74 and "BAD-SN" not in out
    assert "BAD-SN" in client.item_errors and "400" in client.item_errors["BAD-SN"]


def test_coverage_pagination():
    client = cisco.CiscoClient("id", "secret", session=RoutingSession(pages=2))
    out = client.coverage(["FOC00000001", "FOC00000002", "FOC00000003"])
    assert set(out) == {"FOC00000001", "FOC00000002", "FOC00000003"}


def test_pids_are_url_encoded():
    session = RoutingSession()
    cisco.CiscoClient("id", "secret", session=session).coverage(["ISR4331/K9"])
    assert "ISR4331%2FK9" in session.urls[0]


def test_per_serial_error_kept():
    out = cisco.parse_coverage({"serial_numbers": [
        {"sr_no": "FOC1", "ErrorResponse": {"APIError": {"ErrorCode": "API_SNI_0002",
                                                          "ErrorDescription": "Not entitled to this serial"}}},
        {"sr_no": "FOC2", "is_covered": "NO"}]})
    assert out["FOC1"] == {"error": "API_SNI_0002 Not entitled to this serial"}
    assert out["FOC2"]["covered"] is False
    assert not cisco.has_data(out["FOC1"])  # errors are retried like misses


def test_invalid_serials_not_sent(tmp_path):
    class Fake:
        item_errors = {}

        def __init__(self):
            self.sent = []

        def coverage(self, serials):
            self.sent += serials
            return {}

        def software(self, pids):
            return {}

    fake = Fake()
    logs = []
    cisco.refresh(fake, ["FOC12345678", "N/A?", "AB"], [], tmp_path, log=logs.append)
    assert fake.sent == ["FOC12345678"]
    assert any("Skipping 2 serial" in line for line in logs)
    assert cisco.load_cache(tmp_path)["last_run"]["sections"]["coverage"]["sent"] == 1


# ---- diagnostics report -------------------------------------------------------------------

@pytest.fixture
def diag_cache(tmp_path):
    shutil.copy(FIXTURES / "vulns_sample.json", tmp_path / export.VULNS_FILE)
    shutil.copy(FIXTURES / "assets_sample.json", tmp_path / export.ASSETS_FILE)
    rows, devices = akips.inventory_from_raw(json.loads((FIXTURES / "akips_raw_sample.json").read_text()))
    inventory._write(tmp_path, inventory.AKIPS_FILE, rows, devices=devices)
    inventory._write(tmp_path, inventory.TENABLE_FILE, inventory.parse_tenable_inventory(
        json.loads((FIXTURES / "tenable_inventory_sample.json").read_text())))
    coverage = {k: {**v, "fetched_at": STAMP} for k, v in cisco.parse_coverage(
        json.loads((FIXTURES / "cisco_coverage_sample.json").read_text())).items()}
    coverage["FOC2333X1ZZ"] = {"error": "API_SNI_0002 Not entitled", "fetched_at": STAMP}
    software = {"C9300-48P": {"releases": [{"release": "17.12.4", "suggested": True, "software_type": "IOS XE"}],
                              "fetched_at": STAMP},
                "WS-C2960X-48FPD-L": {"releases": [], "fetched_at": STAMP},
                "WS-C3750X-48P-S": {"releases": [{"release": "15.2.4E10", "suggested": True}], "fetched_at": STAMP}}
    cisco.save_cache(tmp_path, {"coverage": coverage, "software": software, "eox_serial": {}, "eox_pid": {},
                                "last_run": {"at": STAMP, "apis": ["sn2info", "software"],
                                             "sections": {"coverage": {"sent": 5, "found": 4}}, "errors": []}})
    return tmp_path


def test_enrichment_report_stages(diag_cache, monkeypatch):
    monkeypatch.chdir(diag_cache)
    monkeypatch.delenv("CISCO_APIS", raising=False)
    funnel, devices, unmatched = diagnostics.enrichment_report(diag_cache)
    stage = dict(zip(devices["hostname"], devices["stage"]))
    reason = dict(zip(devices["hostname"], devices["reason"]))
    assert stage["core-sw-01"] == "OK"
    assert stage["core-sw-02"] == "Cisco: error" and "API_SNI_0002" in reason["core-sw-02"]
    assert stage["edge-fw-01"] == "Not Cisco"
    assert stage["dist-rtr-01"] == "Not matched to AKiPS"
    assert stage["lab-sw-01"] == "Software: no suggestion"  # contract OK, no release for the 2960X
    # one member's serial was looked up (not covered), the other's never was
    assert stage["old-sw-07"] == "Not looked up yet" and "FDO1234A5BD" in reason["old-sw-07"]
    assert "1 of 2 members" in reason["old-sw-07"]
    assert list(unmatched["akips_device"]) == ["lab-sw-01"]
    assert funnel["identified as Cisco"] == 3 and funnel["Cisco, fully enriched"] == 1  # Tenable devices only
    counts = diagnostics.stage_counts(devices).set_index("stage")["devices"]
    assert counts["Not matched to AKiPS"] == 2 and counts["OK"] == 1
    assert all(diagnostics.HINTS[s] for s in counts.index if s != "OK")


def test_report_respects_disabled_api(diag_cache, monkeypatch):
    monkeypatch.chdir(diag_cache)
    monkeypatch.setenv("CISCO_APIS", "software")
    _f, devices, _u = diagnostics.enrichment_report(diag_cache)
    assert dict(zip(devices["hostname"], devices["stage"]))["core-sw-02"] in ("Not looked up yet", "API not enabled")


def test_scrubbed_bundle_has_no_identifiers(diag_cache, monkeypatch):
    monkeypatch.chdir(diag_cache)
    path = diagnostics.export_bundle(diag_cache, diag_cache / "bundle.zip")
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
        text = "".join(zf.read(n).decode() for n in names)
    assert {"devices.csv", "stages.csv", "unmatched_akips_devices.csv", "akips_devices.csv"} <= set(names)
    for secret in ("core-sw-01", "lab-sw-01", "10.0.0.1", "10.9.0.5", "FOC2401X0AA", "FDO1234A5BC"):
        assert secret not in text
    assert "host-" in text and "sn-" in text


def test_cli_enrichment_report(diag_cache, monkeypatch, capsys):
    from tenable_net import cli

    monkeypatch.chdir(diag_cache)
    assert cli.main(["--cache-dir", str(diag_cache), "enrichment-report"]) == 0
    assert cli.main(["--cache-dir", str(diag_cache), "enrichment-report", "--device", "core-sw-02",
                     "--bundle", str(diag_cache / "b.zip")]) == 0
    assert (diag_cache / "b.zip").exists()
