import json
from pathlib import Path

import pandas as pd
import pytest

from tenable_net import export, history, normalize

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def findings():
    return normalize.findings_frame(json.loads((FIXTURES / "vulns_sample.json").read_text()))


def snap(tmp_path, frame, when):
    return history.save(tmp_path, history.build_snapshot(frame, pd.Timestamp(when, tz="UTC").isoformat()))


def test_snapshot_contents(findings):
    s = history.build_snapshot(findings, "2026-10-30T00:00:00+00:00")
    assert s["counts"] == {"critical": 3, "high": 2, "medium": 1, "low": 1}
    assert len(s["items"]) == 7 and s["exploitable"] == 3
    assert set(s["devices"]) == {"core-sw-01", "core-sw-02", "edge-fw-01", "dist-rtr-01"}
    key = next(iter(s["items"]))
    assert key.count(":") == 2 and "/" in key


def test_changes_new_fixed_reopened(tmp_path, findings):
    junos = findings["plugin_id"] == 200001
    snap(tmp_path, findings, "2026-10-01")                     # all present
    snap(tmp_path, findings[~junos].iloc[1:], "2026-10-08")   # Junos fixed + one more gone
    assert history.changes(tmp_path)["fixed"].shape[0] == 2
    snap(tmp_path, findings.iloc[1:], "2026-10-15")           # Junos back = reopened
    c = history.changes(tmp_path)
    assert list(c["reopened"]["plugin_id"]) == [200001] and c["new"].empty and c["fixed"].empty
    assert c["deltas"]["high"] == 1


def test_changes_needs_two_snapshots(tmp_path, findings):
    assert history.changes(tmp_path) is None
    snap(tmp_path, findings, "2026-10-01")
    assert history.changes(tmp_path) is None


def test_series_and_time_to_fix(tmp_path, findings):
    snap(tmp_path, findings, "2026-10-01")
    snap(tmp_path, findings[findings["severity"].astype(str) != "critical"], "2026-11-30")
    s = history.series(tmp_path)
    assert list(s["critical"]) == [3, 0] and s["fixed"].iloc[1] == 3 and pd.isna(s["new"].iloc[0])
    ttf = history.time_to_fix(tmp_path).set_index("severity")
    # fixture first_found is 2026-08-01 -> gone by 2026-11-30
    assert ttf.loc["critical", "fixed"] == 3 and ttf.loc["critical", "mean_days"] == pytest.approx(121, abs=1)
    assert history.series(tmp_path, days=10).shape[0] == 1


def test_retention(tmp_path, findings):
    for day in range(1, 8):
        snap(tmp_path, findings, f"2026-10-{day:02d}")
    history.prune(tmp_path, keep=3)
    assert [p.name[:8] for p in history.list_snapshots(tmp_path)] == ["20261005", "20261006", "20261007"]


def test_pull_records_history_and_backfill(tmp_path):
    vulns = json.loads((FIXTURES / "vulns_sample.json").read_text())

    class Tio:
        class exports:  # noqa: N801
            @staticmethod
            def vulns(**_k):
                return iter(vulns)

            @staticmethod
            def assets(**_k):
                return iter([])

    export.pull(Tio(), ["critical"], ["open"], cache_dir=tmp_path)
    assert len(history.list_snapshots(tmp_path)) == 1
    assert history.record(tmp_path) is None  # same pull isn't recorded twice
    other = tmp_path / "other"
    export.save_cache(vulns, [], {}, other)
    assert history.ensure_backfill(other) is not None and len(history.list_snapshots(other)) == 1


def test_device_trend(tmp_path, findings):
    snap(tmp_path, findings, "2026-10-01")
    snap(tmp_path, findings[findings["hostname"] != "core-sw-01"], "2026-10-08")
    snap(tmp_path, findings, "2026-10-15")
    assert len(history.device_trend(tmp_path, "core-sw-01")) == 2
    assert len(history.device_trend(tmp_path, "edge-fw-01")) == 3
