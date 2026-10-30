"""Pull history: a compact snapshot per pull, and what changed between them.

Each snapshot (cache/history/<UTC timestamp>.json.gz, a few hundred KB at most) stores the open findings
as keys "asset:plugin:port/proto" with severity, host and first-found date, plus counts by severity and
per-device risk scores. From consecutive snapshots we derive new / fixed / reopened findings, trend
series and mean time to fix. The newest MAX_SNAPSHOTS are kept.
"""

import gzip
import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from tenable_net import export, normalize, risk

HISTORY_DIR = "history"
MAX_SNAPSHOTS = 90
SEVERITIES = ["critical", "high", "medium", "low"]


def _dir(cache_dir):
    return Path(cache_dir) / HISTORY_DIR


def finding_key(row):
    return f"{row.get('asset_uuid')}:{row.get('plugin_id')}:{row.get('port') or 0}/{row.get('protocol') or ''}"


def build_snapshot(findings, pulled_at, hardware=None):
    """Snapshot dict from a findings frame (open/reopened, non-info)."""
    f = findings[(findings["severity"].astype(str) != "info") & (findings["state"] != "FIXED")]
    if "risk" not in f:
        f = risk.add_finding_scores(f)
    items = {}
    for r in f.to_dict("records"):
        first = r.get("first_found")
        items[finding_key(r)] = {
            "s": str(r["severity"]), "h": r.get("hostname"), "p": r.get("plugin_id"), "n": r.get("plugin_name"),
            "f": first.isoformat() if isinstance(first, pd.Timestamp) and not pd.isna(first) else None,
            "r": float(r.get("risk") or 0),
        }
    devices = risk.device_scores(f, hardware)
    counts = f["severity"].astype(str).value_counts()
    return {
        "at": pulled_at,
        "counts": {s: int(counts.get(s, 0)) for s in SEVERITIES},
        "exploitable": int((f["exploit_available"] == True).sum()),  # noqa: E712
        "fleet": risk.fleet_summary(devices),
        "devices": {r["hostname"]: r["risk"] for r in devices.to_dict("records")},
        "items": items,
    }


def _path_for(cache_dir, pulled_at):
    try:
        stamp = datetime.fromisoformat(pulled_at).astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    except (TypeError, ValueError):
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return _dir(cache_dir) / f"{stamp}.json.gz"


def save(cache_dir, snapshot):
    path = _path_for(cache_dir, snapshot["at"])
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wt", encoding="utf-8") as fh:
        json.dump(snapshot, fh, separators=(",", ":"))
    prune(cache_dir)
    return path


def prune(cache_dir, keep=MAX_SNAPSHOTS):
    paths = list_snapshots(cache_dir)
    for old in paths[:-keep] if len(paths) > keep else []:
        old.unlink(missing_ok=True)


def list_snapshots(cache_dir):
    d = _dir(cache_dir)
    return sorted(d.glob("*.json.gz")) if d.exists() else []


def load(path):
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        return json.load(fh)


def record(cache_dir, hardware=None):
    """Snapshot the current cache (called after every pull). Returns the path, or None if unchanged/absent."""
    try:
        vulns, _assets, meta = export.load_cache(cache_dir)
    except FileNotFoundError:
        return None
    pulled_at = meta.get("pulled_at") or datetime.now(timezone.utc).isoformat(timespec="seconds")
    path = _path_for(cache_dir, pulled_at)
    if path.exists():
        return None
    findings = normalize.findings_frame(vulns, include_info=False)
    return save(cache_dir, build_snapshot(findings, pulled_at, hardware))


def ensure_backfill(cache_dir):
    """First run after upgrading: create a snapshot from the existing cache so history starts now."""
    if not list_snapshots(cache_dir):
        return record(cache_dir)
    return None


# ---- comparisons ------------------------------------------------------------------------

def changes(cache_dir):
    """What changed between the last two snapshots.

    Returns None with fewer than two snapshots, else a dict with 'previous_at', 'at', and DataFrames
    'new', 'fixed', 'reopened' (key, hostname, plugin_id, plugin_name, severity, risk) plus 'deltas'."""
    paths = list_snapshots(cache_dir)
    if len(paths) < 2:
        return None
    current, previous = load(paths[-1]), load(paths[-2])
    earlier = set()
    for p in paths[:-2][-30:]:  # reopened = absent last time but seen in an earlier snapshot
        earlier |= set(load(p)["items"])
    cur, prev = set(current["items"]), set(previous["items"])

    def frame(keys, source):
        rows = [{"key": k, "hostname": source[k]["h"], "plugin_id": source[k]["p"], "plugin_name": source[k]["n"],
                 "severity": source[k]["s"], "risk": source[k]["r"]} for k in keys]
        df = pd.DataFrame(rows, columns=["key", "hostname", "plugin_id", "plugin_name", "severity", "risk"])
        return df.sort_values("risk", ascending=False).reset_index(drop=True)

    appeared = cur - prev
    reopened = {k for k in appeared if k in earlier}
    deltas = {s: current["counts"].get(s, 0) - previous["counts"].get(s, 0) for s in SEVERITIES}
    deltas["exploitable"] = current.get("exploitable", 0) - previous.get("exploitable", 0)
    deltas["fleet"] = round(current["fleet"]["index"] - previous["fleet"]["index"], 1)
    for b in ("Critical", "High"):
        deltas[b] = current["fleet"]["counts"].get(b, 0) - previous["fleet"]["counts"].get(b, 0)
    return {
        "previous_at": previous["at"], "at": current["at"],
        "new": frame(appeared - reopened, current["items"]),
        "reopened": frame(reopened, current["items"]),
        "fixed": frame(prev - cur, previous["items"]),
        "deltas": deltas,
        "new_keys": appeared,
    }


def series(cache_dir, days=None):
    """One row per snapshot: counts by severity, exploitable, fleet index, devices at Critical/High risk,
    and new / fixed counts vs. the previous snapshot."""
    rows, prev_items = [], None
    for path in list_snapshots(cache_dir):
        snap = load(path)
        items = set(snap["items"])
        rows.append({
            "at": pd.Timestamp(snap["at"]),
            **{s: snap["counts"].get(s, 0) for s in SEVERITIES},
            "exploitable": snap.get("exploitable", 0),
            "fleet": snap["fleet"]["index"],
            "at_risk": snap["fleet"]["counts"].get("Critical", 0) + snap["fleet"]["counts"].get("High", 0),
            "new": len(items - prev_items) if prev_items is not None else None,
            "fixed": len(prev_items - items) if prev_items is not None else None,
        })
        prev_items = items
    df = pd.DataFrame(rows, columns=["at", *SEVERITIES, "exploitable", "fleet", "at_risk", "new", "fixed"])
    if days and not df.empty:
        df = df[df["at"] >= df["at"].max() - pd.Timedelta(days=days)]
    return df.reset_index(drop=True)


def time_to_fix(cache_dir):
    """Mean / median days from first found to the first snapshot where the finding is gone, by severity."""
    paths = list_snapshots(cache_dir)
    durations = []
    prev = None
    for path in paths:
        snap = load(path)
        if prev is not None:
            fixed_at = pd.Timestamp(snap["at"])
            for key in set(prev["items"]) - set(snap["items"]):
                item = prev["items"][key]
                if item.get("f"):
                    durations.append({"severity": item["s"],
                                      "days": max((fixed_at - pd.Timestamp(item["f"])).days, 0)})
        prev = snap
    df = pd.DataFrame(durations, columns=["severity", "days"])
    if df.empty:
        return pd.DataFrame(columns=["severity", "fixed", "mean_days", "median_days"])
    out = df.groupby("severity")["days"].agg(fixed="count", mean_days="mean", median_days="median").reset_index()
    out["severity"] = pd.Categorical(out["severity"], SEVERITIES, ordered=True)
    return out.sort_values("severity").reset_index(drop=True)


def device_trend(cache_dir, hostname, last=12):
    """[(at, risk)] for one device over the most recent snapshots."""
    out = []
    for path in list_snapshots(cache_dir)[-last:]:
        snap = load(path)
        if hostname in snap["devices"]:
            out.append((snap["at"], snap["devices"][hostname]))
    return out
