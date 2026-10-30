import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import pytest

from tenable_net import normalize, risk

FIXTURES = Path(__file__).parent / "fixtures"
NOW = datetime(2026, 10, 30, tzinfo=timezone.utc)


def finding(**kw):
    base = {"hostname": "h", "plugin_name": "p", "severity": "high", "vpr": None, "cvss3": None,
            "exploit_available": False, "first_found": None}
    base.update(kw)
    return base


def test_finding_score_parts_add_up():
    row = finding(vpr=9.8, exploit_available=True, first_found=pd.Timestamp(NOW - timedelta(days=90)))
    score, parts = risk.score_finding(row, NOW)
    assert score == pytest.approx(88.2 + 6 + 2)
    assert sum(p for _l, p in parts) == pytest.approx(score)
    assert [label for label, _p in parts] == ["VPR 9.8", "public exploit available", "open 90 days"]


@pytest.mark.parametrize("row,expected", [
    (finding(vpr=None, cvss3=7.5), 67.5),                      # CVSS when no VPR
    (finding(severity="medium"), 42.0),                         # severity default when neither
    (finding(severity="info"), 0.0),
    (finding(vpr=10, exploit_available=True, first_found=pd.Timestamp(NOW - timedelta(days=900))), 100.0),
])
def test_finding_score_inputs(row, expected):
    assert risk.score_finding(row, NOW)[0] == pytest.approx(expected)


def test_device_score_diminishing_and_hardware():
    one = pd.DataFrame([finding(hostname="a", risk=90.0)])
    many_mediums = pd.DataFrame([finding(hostname="b", risk=45.0) for _ in range(30)])
    scores = risk.device_scores(pd.concat([one, many_mediums])).set_index("hostname")["risk"]
    assert scores["a"] > scores["b"]  # 30 mediums don't outweigh one critical
    hw = pd.DataFrame([{"hostname": "a", "contract": "Not covered", "lifecycle": "", "sw_status": "Upgrade suggested"}])
    with_hw = risk.device_scores(one, hw).set_index("hostname")["risk"]
    assert with_hw["a"] == pytest.approx(90 * 0.8 + 8 + 4)


def test_explain_device_matches_score():
    v = json.loads((FIXTURES / "vulns_sample.json").read_text())
    f = risk.add_finding_scores(normalize.findings_frame(v), NOW)
    devices = risk.device_scores(f).set_index("hostname")
    for host in devices.index:
        parts, detail = risk.explain_device(host, f, now=NOW)
        assert min(sum(p for _l, p in parts), 100) == pytest.approx(devices.loc[host, "risk"], abs=0.11)
        assert detail and detail[0][1]
    assert devices.loc["edge-fw-01", "risk_band"] == "Critical"
    assert devices.loc["dist-rtr-01", "risk_band"] == "High"


def test_bands_and_fleet_summary():
    assert [risk.band(s) for s in (90, 75, 60, 30, 10, 0)] == ["Critical", "Critical", "High", "Elevated", "Low", "Low"]
    d = pd.DataFrame({"hostname": list("abcd"), "risk": [90.0, 60.0, 30.0, 5.0],
                      "risk_band": ["Critical", "High", "Elevated", "Low"]})
    s = risk.fleet_summary(d)
    assert s["index"] == 90.0 and s["band"] == "Critical"
    assert s["counts"] == {"Critical": 1, "High": 1, "Elevated": 1, "Low": 1}
    assert risk.fleet_summary(pd.DataFrame(columns=["risk", "risk_band"]))["devices"] == 0


def test_add_finding_scores_columns():
    v = json.loads((FIXTURES / "vulns_sample.json").read_text())
    f = risk.add_finding_scores(normalize.findings_frame(v, include_info=True), NOW)
    assert {"risk", "days_open"} <= set(f.columns)
    assert f.loc[f["severity"] == "info", "risk"].eq(0).all()
    assert f["risk"].between(0, 100).all()
