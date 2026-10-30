import json
import shutil
from datetime import date
from pathlib import Path

import pytest

from tenable_net import akips, cisco, export, inventory

FIXTURES = Path(__file__).parent / "fixtures"
TODAY = date(2026, 10, 30)


def fixture(name):
    return json.loads((FIXTURES / name).read_text())


@pytest.fixture
def akips_rows():
    return akips.rows_from_raw(fixture("akips_raw_sample.json"))


@pytest.fixture
def tenable_rows():
    return inventory.parse_tenable_inventory(fixture("tenable_inventory_sample.json"))


@pytest.fixture
def device_index():
    return inventory.tenable_device_index(fixture("vulns_sample.json"), fixture("assets_sample.json"))


@pytest.fixture
def cisco_cache():
    cache = {"coverage": cisco.parse_coverage(fixture("cisco_coverage_sample.json")),
             "eox_serial": cisco.parse_eox(fixture("cisco_eox_sample.json")),
             "eox_pid": {}}
    return cache


# ---- AKiPS ----------------------------------------------------------------

def test_parse_mget():
    lines = akips.parse_mget('dev1 sys SNMPv2-MIB.sysDescr = Cisco IOS "x"\ngarbage line\ndev2 1 attr =\n')
    assert lines[0] == ("dev1", "sys", "SNMPv2-MIB.sysDescr", 'Cisco IOS "x')
    assert lines[1] == ("dev2", "1", "attr", "")


def test_akips_chassis_rows(akips_rows):
    by_device = {}
    for r in akips_rows:
        by_device.setdefault(r["akips_device"], []).append(r)
    stack = by_device["core-sw-01"]
    # only the two chassis members: no stack container, module or PSU
    assert [(r["member"], r["serial"], r["model"]) for r in stack] == [
        (1, "FOC2401X0AA", "C9300-48P"), (2, "FOC2401X0BB", "C9300-48P")]
    assert stack[0]["ip"] == "10.0.0.1" and "CAT9K" in stack[0]["sys_descr"]
    assert by_device["lab-sw-01"][0]["model"] == "WS-C2960X-48FPD-L"
    assert len(akips_rows) == 4


def test_chassis_class_numeric():
    rows = akips.chassis_rows([], [("d", "5", "ENTITY-MIB.entPhysicalClass", "3"),
                                  ("d", "5", "ENTITY-MIB.entPhysicalSerialNum", "SN1"),
                                  ("d", "6", "ENTITY-MIB.entPhysicalClass", "chassis(3)"),
                                  ("d", "6", "ENTITY-MIB.entPhysicalSerialNum", "SN2"),
                                  ("d", "7", "ENTITY-MIB.entPhysicalClass", "port(10)"),
                                  ("d", "7", "ENTITY-MIB.entPhysicalSerialNum", "SN3")])
    assert [r["serial"] for r in rows] == ["SN1", "SN2"]


# ---- Tenable plugin output -------------------------------------------------

def test_parse_plugin_output_key_values():
    rows = inventory.parse_plugin_output("  Version : 17.6.1\n  Model   : C9300-24T\n  Serial Number : FOC2333X1ZZ\n")
    assert rows == [{"model": "C9300-24T", "serial": "FOC2333X1ZZ", "sw_version": "17.6.1"}]


def test_parse_plugin_output_stack_show_version(tenable_rows):
    old = [r for r in tenable_rows if r["hostname"] == "old-sw-07"]
    assert [(r["member"], r["model"], r["serial"]) for r in old] == [
        (1, "WS-C3750X-48P-S", "FDO1234A5BC"), (2, "WS-C3750X-48P-S", "FDO1234A5BD")]


def test_parse_plugin_output_model_only(tenable_rows):
    core1 = [r for r in tenable_rows if r["hostname"] == "core-sw-01"]
    assert core1 == [{"asset_uuid": "uuid-core-sw-01", "hostname": "core-sw-01", "ip": "10.0.0.1", "member": 1,
                      "plugin_id": 67217, "model": "C9300-48P", "serial": "", "sw_version": "17.9.4a"}]
    assert inventory.parse_plugin_output("") == []
    assert inventory.parse_plugin_output(None) == []


# ---- join --------------------------------------------------------------------

def test_build_inventory(akips_rows, tenable_rows, device_index):
    inv = inventory.build_inventory(akips_rows, tenable_rows, device_index)
    core1 = inv[inv["hostname"] == "core-sw-01"]
    assert list(core1["source"]) == ["AKiPS", "AKiPS"]  # AKiPS wins over Tenable for the same device
    assert core1["in_tenable"].all()
    assert inv.loc[inv["hostname"] == "edge-fw-01", "vendor"].item() == "Palo Alto"
    lab = inv[inv["hostname"] == "lab-sw-01"]
    assert not lab["in_tenable"].item()  # AKiPS-only device
    core2 = inv[inv["hostname"] == "core-sw-02"]
    assert core2["source"].item() == "Tenable 67217" and core2["serial"].item() == "FOC2333X1ZZ"
    assert len(inv[inv["hostname"] == "old-sw-07"]) == 2


def test_join_by_hostname_when_ip_differs(device_index):
    rows = [{"akips_device": "CORE-SW-01.net.example.edu", "ip": "192.0.2.99", "sys_descr": "Cisco IOS",
             "member": 1, "model": "C9300-48P", "serial": "X1", "sw_version": ""}]
    inv = inventory.build_inventory(rows, [], device_index)
    assert inv["hostname"].item() == "core-sw-01" and inv["in_tenable"].item()


# ---- Cisco enrichment ----------------------------------------------------------

def test_parse_eox_and_coverage(cisco_cache):
    eox = cisco_cache["eox_serial"]
    assert eox["FOC1950W0EE"]["ldos"] == "2027-10-31"
    assert eox["FOC1950W0EE"]["migration_pid"] == "C9200L-48P-4G-E"
    assert eox["FDO1234A5BD"]["ldos"] == "2021-10-31"  # comma-separated EOXInputValue
    assert eox["FOC2401X0AA"]["eox_status"] == "No EoX announced"
    cov = cisco_cache["coverage"]
    assert cov["FOC2401X0AA"]["covered"] is True and cov["FOC2401X0AA"]["orderable_pid"] == "C9300-48P-E"
    assert cov["FOC2401X0BB"]["covered"] is False


def test_enrich_and_summary(akips_rows, tenable_rows, device_index, cisco_cache):
    inv = inventory.enrich(inventory.build_inventory(akips_rows, tenable_rows, device_index), cisco_cache, TODAY)
    row = lambda serial: inv[inv["serial"] == serial].iloc[0]
    assert row("FOC1950W0EE")["lifecycle"] == "End of sale"   # LDoS 2027-10-31 is > 12 months out
    assert row("FDO1234A5BC")["lifecycle"] == "Past LDoS"
    assert row("FOC2401X0AA")["lifecycle"] == "Current"
    assert row("FOC2401X0AA")["contract"] == "Covered"
    assert row("FOC2401X0BB")["contract"] == "Not covered"
    assert row("FOC2333X1ZZ")["contract"] == "Unknown"
    assert inv.loc[inv["hostname"] == "edge-fw-01", "contract"].item() == ""  # non-Cisco: not looked up

    summary = inventory.device_summary(inv).set_index("hostname")
    assert summary.loc["core-sw-01", "members"] == 2
    assert summary.loc["core-sw-01", "contract"] == "Not covered"  # one member uncovered
    assert summary.loc["old-sw-07", "lifecycle"] == "Past LDoS"
    assert not summary.loc["lab-sw-01", "in_tenable"]


def test_lifecycle_status():
    assert inventory.lifecycle_status({"ldos": "2027-03-01"}, TODAY) == "LDoS < 12 mo"
    assert inventory.lifecycle_status({}, TODAY) == "Unknown"
    assert inventory.lifecycle_status({"end_of_sale": "2030-01-01", "eox_status": "Announced"}, TODAY) == "EoX announced"


def test_cisco_keys_cisco_only(akips_rows, tenable_rows, device_index):
    serials, pids = inventory.cisco_keys(inventory.build_inventory(akips_rows, tenable_rows, device_index))
    assert "013201012345" not in serials  # Palo Alto serial
    assert {"FOC2401X0AA", "FOC1950W0EE", "FDO1234A5BD"} <= set(serials)
    assert "PA-3220" not in pids


# ---- Cisco client (mocked HTTP) --------------------------------------------------

class FakeResponse:
    def __init__(self, status, body=None, headers=None):
        self.status_code, self._body, self.headers = status, body or {}, headers or {}

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeSession:
    def __init__(self, gets):
        self.gets = list(gets)
        self.get_urls, self.posts = [], 0

    def post(self, url, data=None, timeout=None):
        self.posts += 1
        return FakeResponse(200, {"access_token": f"tok{self.posts}", "expires_in": 3600})

    def get(self, url, headers=None, timeout=None):
        self.get_urls.append(url)
        return self.gets.pop(0)


def test_cisco_client_batches_and_retries(monkeypatch):
    monkeypatch.setattr(cisco.time, "sleep", lambda s: None)
    cov = fixture("cisco_coverage_sample.json")
    session = FakeSession([FakeResponse(429, headers={"Retry-After": "0"}), FakeResponse(200, cov),
                           FakeResponse(200, {"serial_numbers": []})])
    client = cisco.CiscoClient("id", "secret", session=session)
    serials = [f"S{i}" for i in range(80)]  # > 75 -> two batches
    out = client.coverage(serials)
    assert out["FOC2401X0AA"]["covered"] is True
    assert len(session.get_urls) == 3 and session.posts == 1
    assert session.get_urls[1].endswith(",".join(serials[:75]))
    assert session.get_urls[2].endswith("S75,S76,S77,S78,S79")


def test_cisco_client_eox_pagination():
    page1 = {"PaginationResponseRecord": {"LastIndex": 2},
             "EOXRecord": [{"EOXInputValue": "A", "LastDateOfSupport": {"value": "2020-01-01"}}]}
    page2 = {"PaginationResponseRecord": {"LastIndex": 2},
             "EOXRecord": [{"EOXInputValue": "B", "LastDateOfSupport": {"value": "2021-01-01"}}]}
    session = FakeSession([FakeResponse(200, page1), FakeResponse(200, page2)])
    out = cisco.CiscoClient("id", "secret", session=session).eox_by_pid(["A", "B"])
    assert out["B"]["ldos"] == "2021-01-01"
    assert "/EOXByProductID/2/A,B" in session.get_urls[1]


class CountingCisco:
    def __init__(self):
        self.calls = []

    def coverage(self, serials):
        self.calls.append(("coverage", serials))
        return {s: {"covered": True} for s in serials}

    def eox_by_serial(self, serials):
        self.calls.append(("eox_serial", serials))
        return {}

    def eox_by_pid(self, pids):
        self.calls.append(("eox_pid", pids))
        return {}


def test_cisco_refresh_uses_cache_ttl(tmp_path):
    fake = CountingCisco()
    cisco.refresh(fake, ["s1", "S2"], ["PID1"], tmp_path)
    assert ("coverage", ["S1", "S2"]) in fake.calls
    fake.calls.clear()
    cisco.refresh(fake, ["S1", "S2", "S3"], ["PID1"], tmp_path)  # only the new serial is queried
    assert fake.calls == [("coverage", ["S3"]), ("eox_serial", ["S3"])]
    fake.calls.clear()
    cisco.refresh(fake, ["S1"], [], tmp_path, force=True)
    assert ("coverage", ["S1"]) in fake.calls
    assert cisco.load_cache(tmp_path)["coverage"]["S1"]["covered"] is True


# ---- cache round trip --------------------------------------------------------------

class FakeAkips:
    def raw_responses(self):
        return fixture("akips_raw_sample.json")


class FakeTio:
    class exports:  # noqa: N801
        @staticmethod
        def vulns(**kwargs):
            assert kwargs["plugin_id"] == [67217, 47864] and kwargs["include_plugin_output"]
            return iter(fixture("tenable_inventory_sample.json"))


def test_refresh_and_load_inventory(tmp_path):
    shutil.copy(FIXTURES / "vulns_sample.json", tmp_path / export.VULNS_FILE)
    shutil.copy(FIXTURES / "assets_sample.json", tmp_path / export.ASSETS_FILE)
    assert inventory.load_inventory(tmp_path).empty
    summary = inventory.refresh(tmp_path, tio=FakeTio(), akips_client=FakeAkips(), samples=2)
    assert summary == {"akips_chassis": 4, "tenable_chassis": 4}
    assert (tmp_path / "samples" / "akips_raw.txt").exists()
    assert (tmp_path / "samples" / "tenable_inventory_sample.json").exists()
    inv = inventory.load_inventory(tmp_path, today=TODAY)
    assert set(inv["hostname"]) == {"core-sw-01", "core-sw-02", "edge-fw-01", "lab-sw-01", "old-sw-07"}
    assert {"contract", "ldos", "lifecycle"} <= set(inv.columns)
