import json
import shutil
from datetime import date
from pathlib import Path

import pandas as pd
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

    def software(self, pids):
        self.calls.append(("software", sorted(pids)))
        return {}


ALL_APIS = {"sn2info", "software", "eox"}


def test_cisco_refresh_uses_cache_ttl(tmp_path):
    fake = CountingCisco()
    apis = {"sn2info", "eox"}
    cisco.refresh(fake, ["s1", "S2"], ["PID1"], tmp_path, apis=apis)
    assert ("coverage", ["S1", "S2"]) in fake.calls
    fake.calls.clear()
    cisco.refresh(fake, ["S1", "S2", "S3"], ["PID1"], tmp_path, apis=apis)  # only the new serial is queried
    assert fake.calls == [("coverage", ["S3"]), ("eox_serial", ["S3"])]
    fake.calls.clear()
    cisco.refresh(fake, ["S1"], [], tmp_path, force=True, apis=apis)
    assert ("coverage", ["S1"]) in fake.calls
    assert cisco.load_cache(tmp_path)["coverage"]["S1"]["covered"] is True


# ---- cache round trip --------------------------------------------------------------

class FakeAkips:
    def raw_responses(self, log=None):
        return fixture("akips_raw_sample.json")

    def device_dump(self, device):
        return f"{device} sys SNMPv2-MIB.sysDescr = test\n"


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
    assert list((tmp_path / "samples").glob("akips_device_*.txt"))
    inv = inventory.load_inventory(tmp_path, today=TODAY)
    assert set(inv["hostname"]) == {"core-sw-01", "core-sw-02", "edge-fw-01", "lab-sw-01", "old-sw-07"}
    assert {"contract", "ldos", "lifecycle"} <= set(inv.columns)


# ---- robustness fixes: vendor inference, AKiPS fallbacks, Cisco errors -------------------

def test_vendor_inferred_without_sysdescr(device_index):
    rows = [
        {"akips_device": "core-sw-01", "ip": "10.0.0.1", "sys_descr": None, "member": 1, "model": "PA-3220",
         "serial": "X1", "sw_version": ""},  # matched Tenable device runs Cisco IOS XE -> Cisco
        {"akips_device": "lab-sw-01", "ip": "10.9.0.5", "sys_descr": None, "member": 1, "model": "WS-C2960X-48FPD-L",
         "serial": "X2", "sw_version": ""},  # not in Tenable; Cisco by PID shape
        {"akips_device": "lab-fw-01", "ip": "10.9.0.6", "sys_descr": None, "member": 1, "model": "PA-3220",
         "serial": "X3", "sw_version": ""},  # unknown
    ]
    inv = inventory.build_inventory(rows, [], device_index).set_index("akips_device")
    assert inv.loc["core-sw-01", "vendor"] == "Cisco"
    assert inv.loc["lab-sw-01", "vendor"] == "Cisco"
    assert inv.loc["lab-fw-01", "vendor"] == "Unknown"
    serials, pids = inventory.cisco_keys(inv.reset_index())
    assert serials == ["X1", "X2"]


@pytest.mark.parametrize("model", ["C9300-48P", "WS-C3850-48P", "N9K-C93180YC-EX", "ISR4331/K9", "C8300-1N1S-4T2X",
                                   "AIR-AP2802I-B-K9", "ASR1001-X", "C1000-24T-4G-L"])
def test_looks_cisco(model):
    assert inventory.looks_cisco(model)


@pytest.mark.parametrize("model", ["PA-3220", "EX4300-48P", "JL659A", "DCS-7050SX3", "FG-200F", ""])
def test_not_cisco(model):
    assert not inventory.looks_cisco(model)


def test_akips_without_entity_class():
    lines = [("sw1", "1", "ENTITY-MIB.entPhysicalName", "Switch 1"),
             ("sw1", "1", "ENTITY-MIB.entPhysicalModelName", "C9300-48P"),
             ("sw1", "1", "ENTITY-MIB.entPhysicalSerialNum", "SN1"),
             ("sw1", "9", "ENTITY-MIB.entPhysicalName", "Switch 1 - Power Supply A"),
             ("sw1", "9", "ENTITY-MIB.entPhysicalModelName", "PWR-C1-715WAC"),
             ("sw2", "5", "ENTITY-MIB.entPhysicalModelName", "WS-C2960X-48FPD-L"),
             ("sw2", "7", "ENTITY-MIB.entPhysicalModelName", "GLC-SX-MMD")]
    rows = {r["akips_device"]: r for r in akips.chassis_rows([], lines)}
    assert rows["sw1"]["serial"] == "SN1" and rows["sw1"]["model"] == "C9300-48P"
    assert rows["sw2"]["model"] == "WS-C2960X-48FPD-L"  # lowest index with a model
    assert len(akips.chassis_rows([], lines)) == 2


def test_akips_device_level_serial_fallback():
    sys_lines = [("sw1", "sys", "OLD-CISCO-CHASSIS-MIB.chassisId", "FOC9999X0ZZ")]
    lines = [("sw1", "1", "ENTITY-MIB.entPhysicalClass", "chassis"),
             ("sw1", "1", "ENTITY-MIB.entPhysicalModelName", "WS-C3750X-48P-S"),
             ("sw1", "1", "ENTITY-MIB.entPhysicalSerialNum", "")]
    assert akips.chassis_rows(sys_lines, lines)[0]["serial"] == "FOC9999X0ZZ"


def test_cisco_http_error_is_explained():
    session = FakeSession([FakeResponse(403)])
    with pytest.raises(cisco.CiscoApiError, match="403.*isn't enabled"):
        cisco.CiscoClient("id", "secret", session=session).eox_by_pid(["X"])


def test_cisco_error_payload_raises():
    with pytest.raises(cisco.CiscoApiError, match="ErrorResponse"):
        cisco.parse_coverage({"ErrorResponse": {"APIError": {"ErrorCode": "API_SNI_0001"}}})
    with pytest.raises(cisco.CiscoApiError):
        cisco.parse_eox({})


class PartlyEntitledCisco(CountingCisco):
    """Contract lookup works; EoX is not enabled for this API app."""

    def coverage(self, serials):
        self.calls.append(("coverage", serials))
        return {s: {"covered": True, "orderable_pid": "C9300-48P-E"} for s in serials}

    def eox_by_serial(self, serials):
        raise cisco.CiscoApiError("HTTP 403 (this API isn't enabled)")

    def eox_by_pid(self, pids):
        self.calls.append(("eox_pid", sorted(pids)))
        return {"C9300-48P-E": {"ldos": "2030-01-31", "eox_status": "Announced"}}


def test_cisco_refresh_continues_after_one_api_fails(tmp_path):
    fake = PartlyEntitledCisco()
    logs = []
    with pytest.raises(cisco.CiscoApiError, match="EoX by serial"):
        cisco.refresh(fake, ["S1"], ["C9300-48P"], tmp_path, log=logs.append, apis={"sn2info", "eox"})
    cache = cisco.load_cache(tmp_path)
    assert cache["coverage"]["S1"]["covered"] is True          # saved despite the EoX failure
    assert ("eox_pid", ["C9300-48P", "C9300-48P-E"]) in fake.calls  # orderable PID from coverage looked up
    assert cache["eox_pid"]["C9300-48P-E"]["ldos"] == "2030-01-31"
    assert any("WARNING" in line for line in logs)


def test_enrich_uses_orderable_pid():
    inv = pd.DataFrame([{"hostname": "h", "in_tenable": True, "akips_device": "h", "ip": "1", "vendor": "Cisco",
                         "member": 1, "model": "C9300-48P", "serial": "S1", "sw_version": "", "source": "AKiPS"}])
    cache = {"coverage": {"S1": {"covered": True, "orderable_pid": "C9300-48P-E"}},
             "eox_serial": {"S1": {"eox_status": "No EoX announced"}},
             "eox_pid": {"C9300-48P": {"eox_status": "No EoX announced"},
                         "C9300-48P-E": {"ldos": "2025-01-31", "end_of_sale": "2020-01-31", "eox_status": "Announced"}}}
    row = inventory.enrich(inv, cache, TODAY).iloc[0]
    assert row["lifecycle"] == "Past LDoS" and row["contract"] == "Covered"


def test_cisco_misses_retried_after_a_day(tmp_path):
    from datetime import datetime, timedelta, timezone

    old = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat(timespec="seconds")
    cisco.save_cache(tmp_path, {"coverage": {"S1": {"fetched_at": old}, "S2": {"covered": True, "fetched_at": old}},
                                "eox_serial": {}, "eox_pid": {}})
    fake = CountingCisco()
    cisco.refresh(fake, ["S1", "S2"], [], tmp_path)
    assert ("coverage", ["S1"]) in fake.calls  # the 2-day-old miss is retried; the hit is still fresh


class DiagCisco(CountingCisco):
    """Contract lookup not enabled, software suggestions work, EoX not enabled."""

    def token(self):
        return "t"

    def coverage(self, serials):
        raise cisco.CiscoApiError("HTTP 403 (this API isn't enabled for your Cisco API app / contract)")

    def software(self, pids):
        return {p.upper(): {"releases": [{"release": "17.9.5", "suggested": True, "software_type": "IOS XE Software"}]}
                for p in pids}

    def eox_by_pid(self, pids):
        raise cisco.CiscoApiError("HTTP 403 (this API isn't enabled for your Cisco API app / contract)")


def test_cisco_diagnose():
    results = {key: (ok, detail) for key, _name, ok, detail in cisco.diagnose(DiagCisco(), serial="S1", pid="C9300-24T")}
    assert results["token"][0]
    assert results["sn2info"][0] is False and "403" in results["sn2info"][1]
    assert results["software"][0] and "C9300-24T: suggested 17.9.5" in results["software"][1]
    assert results["eox"][0] is False
    skipped = {key: ok for key, _n, ok, _d in cisco.diagnose(DiagCisco())}
    assert skipped["sn2info"] is None


# ---- Software Suggestion v2 + API selection ----------------------------------------------

SOFTWARE_PAYLOAD = {
    "paginationResponseRecord": {"pageIndex": 1, "lastIndex": 1},
    "productList": [
        {"id": "1", "product": {"basePID": "C9300-48P", "productName": "Catalyst 9300 48-port PoE+",
                                "softwareType": "IOS XE Software"},
         "suggestions": [
             {"isSuggested": "Y", "releaseFormat1": "17.9.5", "releaseDate": "30-Mar-2024"},
             {"isSuggested": "Y", "releaseFormat1": "17.12.4", "releaseDate": "12-Nov-2024"},
             {"isSuggested": "N", "releaseFormat1": "17.14.1"},
         ]},
        {"id": "2", "product": {"basePID": "C9300-48P", "softwareType": "IOS XE ROMMON Software"},
         "suggestions": [{"isSuggested": "Y", "releaseFormat1": "17.9.1r"}]},
        {"id": "3", "product": {"basePID": "WS-C2960X-48FPD-L", "softwareType": "IOS Software"},
         "suggestions": [{"isSuggested": "Y", "releaseFormat1": "15.2.7E10"},
                         {"errorDetailsResponse": {"errorCode": "S3_X"}}]},
    ],
}


def test_parse_software_and_suggested_releases():
    out = cisco.parse_software(SOFTWARE_PAYLOAD, ["C9300-48P-E", "WS-C2960X-48FPD-L"])
    assert cisco.suggested_releases(out["C9300-48P"]) == ["17.9.5", "17.12.4"]  # ROMMON + non-suggested left out
    assert out["C9300-48P-E"] is out["C9300-48P"]  # orderable PID mapped to its base PID
    assert cisco.suggested_releases(out["WS-C2960X-48FPD-L"]) == ["15.2.7E10"]
    with pytest.raises(cisco.CiscoApiError, match="S3_INV_BASEPID"):
        cisco.parse_software({"errorResponse": {"errorCode": "S3_INV_BASEPID"}})


@pytest.mark.parametrize("running,suggested,expected", [
    ("17.09.04a", ["17.9.5", "17.12.4"], "Upgrade suggested"),
    ("17.9.5", ["17.9.5", "17.12.4"], "On suggested release"),
    ("17.09.05", ["17.9.5"], "On suggested release"),
    ("17.15.1", ["17.9.5", "17.12.4"], "Newer than suggested"),
    ("15.2(7)E8", ["15.2.7E10"], "Upgrade suggested"),
    ("15.2(7)E10", ["15.2.7E10"], "On suggested release"),
    ("", ["17.9.5"], "Suggestion available"),
    ("17.9.5", [], "No suggestion"),
])
def test_software_status(running, suggested, expected):
    assert inventory.software_status(running, suggested) == expected


def test_software_batch_retried_per_pid():
    bad = FakeResponse(200, {"errorResponse": {"errorCode": "S3_INV_BASEPID"}})
    good = FakeResponse(200, {"productList": [{"product": {"basePID": "C9300-48P"},
                                                "suggestions": [{"isSuggested": "Y", "releaseFormat1": "17.9.5"}]}]})
    session = FakeSession([bad, good, FakeResponse(200, {"errorResponse": {"errorCode": "S3_NO_REC_FOUND"}})])
    out = cisco.CiscoClient("id", "secret", session=session).software(["C9300-48P", "BOGUS-PID"])
    assert cisco.suggested_releases(out["C9300-48P"]) == ["17.9.5"] and "BOGUS-PID" not in out
    assert "/releases/productIds/C9300-48P,BOGUS-PID" in session.get_urls[0]


def test_refresh_software_uses_models_and_base_pids(tmp_path):
    class Fake(CountingCisco):
        def coverage(self, serials):
            self.calls.append(("coverage", serials))
            return {s: {"covered": True, "base_pid": "C9300-48P", "orderable_pid": "C9300-48P-E"} for s in serials}

    fake = Fake()
    cisco.refresh(fake, ["S1"], ["WS-C2960X-48FPD-L"], tmp_path)  # default APIs: sn2info + software
    assert ("software", ["C9300-48P", "WS-C2960X-48FPD-L"]) in fake.calls
    assert not any(call[0].startswith("eox") for call in fake.calls)


def test_enabled_apis(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("CISCO_APIS", raising=False)
    assert cisco.enabled_apis() == {"sn2info", "software"}
    monkeypatch.setenv("CISCO_APIS", "sn2info, EoX, bogus")
    assert cisco.enabled_apis() == {"sn2info", "eox"}
    monkeypatch.setenv("CISCO_APIS", "")
    assert cisco.enabled_apis() == set()


def test_enrich_software_and_contract_fields():
    inv = pd.DataFrame([
        {"hostname": "h", "in_tenable": True, "akips_device": "h", "ip": "1", "vendor": "Cisco", "member": 1,
         "model": "C9300-48P", "serial": "S1", "sw_version": "17.09.04a", "source": "AKiPS"},
        {"hostname": "h2", "in_tenable": True, "akips_device": "h2", "ip": "2", "vendor": "Cisco", "member": 1,
         "model": "C9300-48P", "serial": "", "sw_version": "17.9.5", "source": "AKiPS"},
    ])
    sw = cisco.parse_software(SOFTWARE_PAYLOAD, ["C9300-48P"])
    cache = {"coverage": {"S1": {"covered": True, "contract_end": "2027-06-30", "contract_number": "12345",
                                 "product_line_end": "2030-01-31", "base_pid": "C9300-48P"}},
             "eox_serial": {}, "eox_pid": {}, "software": sw}
    out = inventory.enrich(inv, cache, TODAY).set_index("hostname")
    assert out.loc["h", "sw_status"] == "Upgrade suggested"
    assert out.loc["h", "recommended_sw"] == "17.9.5, 17.12.4"
    assert out.loc["h", "contract_number"] == "12345"
    assert str(out.loc["h", "product_line_end"].date()) == "2030-01-31"
    assert out.loc["h", "lifecycle"] == ""  # no EoX data -> blank, not "Unknown"
    assert out.loc["h2", "sw_status"] == "On suggested release"
    assert out.loc["h2", "contract"] == "No serial"
    assert not inventory.has_lifecycle(out)
    summary = inventory.device_summary(out.reset_index()).set_index("hostname")
    assert summary.loc["h", "sw_status"] == "Upgrade suggested"
