"""Risk scoring: one 0-100 number per finding and per device, with an itemised explanation.

Finding score  = base + exploit + age (0-100, additive so the explanation reads plainly)
    base        = VPR x 9, else CVSS v3 x 9, else a default per severity (max 90)
    exploit     = +6 when public exploit code exists
    age         = up to +4, growing linearly to 180 days open
Device score   = 0.8 x highest finding score (leaves room to tell devices apart)
               + up to 12 for the rest of its findings (diminishing: many mediums can't outweigh one critical)
               + hardware: not under contract, past / near Last Date of Support, Cisco suggests an upgrade
               (capped at 100)
Bands: Critical >= 75, High >= 50, Elevated >= 25, otherwise Low.

All weights live in WEIGHTS so they can be tuned in one place; explain_device() returns the parts
that add up to a device's score, which the app shows as "why this score".
"""

import math
from datetime import datetime, timezone

import pandas as pd

WEIGHTS = {
    "score_scale": 9.0,      # VPR / CVSS (0-10) -> base points (0-90)
    "severity_default": {"critical": 85.0, "high": 65.0, "medium": 42.0, "low": 20.0, "info": 0.0},
    "exploit_points": 6.0,
    "age_max_points": 4.0,
    "age_full_days": 180,
    "top_weight": 0.8,       # share of the highest finding score a device starts from
    "others_max": 12.0,      # most the rest of a device's findings can add
    "others_scale": 150.0,   # sum of other scores that gets ~63% of others_max
    "hardware": {
        "Not covered": ("Hardware not under Cisco contract", 8.0),
        "Past LDoS": ("Past Cisco Last Date of Support", 12.0),
        "LDoS < 12 mo": ("Cisco Last Date of Support within 12 months", 5.0),
        "Upgrade suggested": ("Runs an older release than Cisco suggests", 4.0),
    },
}
BANDS = [(75, "Critical"), (50, "High"), (25, "Elevated"), (0, "Low")]


def band(score):
    if score is None or (isinstance(score, float) and math.isnan(score)) or score <= 0:
        return "Low"
    return next(name for threshold, name in BANDS if score >= threshold)


def _base(row):
    vpr, cvss = row.get("vpr"), row.get("cvss3")
    if pd.notna(vpr) and vpr:
        return float(vpr) * WEIGHTS["score_scale"], f"VPR {float(vpr):.1f}"
    if pd.notna(cvss) and cvss:
        return float(cvss) * WEIGHTS["score_scale"], f"CVSS {float(cvss):.1f}"
    sev = str(row.get("severity"))
    return WEIGHTS["severity_default"].get(sev, 0.0), f"{sev.title()} severity (no VPR/CVSS)"


def days_open(first_found, now=None):
    if first_found is None or pd.isna(first_found):
        return None
    now = now or datetime.now(timezone.utc)
    return max(int((now - pd.Timestamp(first_found).to_pydatetime()).days), 0)


def score_finding(row, now=None):
    """(score, [(label, points)]) for one finding row; the points add up to the score."""
    base, base_label = _base(row)
    if base <= 0:
        return 0.0, [(base_label, 0.0)]
    parts = [(base_label, round(base, 1))]
    exploit = row.get("exploit_available")
    if exploit is True or str(exploit).lower() == "true":
        parts.append(("public exploit available", WEIGHTS["exploit_points"]))
    age = days_open(row.get("first_found"), now)
    if age:
        points = round(WEIGHTS["age_max_points"] * min(age / WEIGHTS["age_full_days"], 1.0), 1)
        if points >= 0.1:
            parts.append((f"open {age} days", points))
    return round(min(sum(p for _l, p in parts), 100.0), 1), parts


def add_finding_scores(findings, now=None):
    """Return findings with 'risk' and 'days_open' columns added.

    Vectorised equivalent of score_finding() (which explains single findings), so 100k findings score in
    well under a second."""
    import numpy as np

    df = findings.copy()
    if df.empty:
        df["risk"], df["days_open"] = pd.Series(dtype=float), pd.Series(dtype="Int64")
        return df
    now = now or datetime.now(timezone.utc)
    scale = WEIGHTS["score_scale"]
    vpr = pd.to_numeric(df.get("vpr"), errors="coerce")
    cvss = pd.to_numeric(df.get("cvss3"), errors="coerce")
    default = df["severity"].astype(str).map(WEIGHTS["severity_default"]).fillna(0.0).astype(float)
    base = np.where(vpr.fillna(0) > 0, vpr * scale, np.where(cvss.fillna(0) > 0, cvss * scale, default))
    base = pd.Series(base, index=df.index).astype(float)
    exploit = df["exploit_available"].astype(str).str.lower().eq("true") if "exploit_available" in df else False
    first = pd.to_datetime(df.get("first_found"), errors="coerce", utc=True)
    age_days = ((pd.Timestamp(now) - first).dt.days).clip(lower=0)
    age_points = (WEIGHTS["age_max_points"] * (age_days / WEIGHTS["age_full_days"]).clip(upper=1.0)).round(1)
    age_points = age_points.where(age_points >= 0.1, 0.0).fillna(0.0)
    score = base + np.where(exploit, WEIGHTS["exploit_points"], 0.0) + age_points
    df["risk"] = score.where(base > 0, 0.0).clip(upper=100.0).round(1)
    df["days_open"] = age_days.astype("Int64")
    return df


def _hardware_flags(hw_row):
    flags = []
    if hw_row is None:
        return flags
    for column in ("contract", "lifecycle", "sw_status"):
        value = hw_row.get(column)
        if isinstance(value, str) and value in WEIGHTS["hardware"]:
            flags.append(WEIGHTS["hardware"][value])
    return flags


def _device_parts(scores, hw_row=None):
    """Itemised parts of a device score from its finding scores (descending)."""
    scores = sorted((s for s in scores if s > 0), reverse=True)
    parts = []
    if scores:
        parts.append((f"Highest-risk finding ({scores[0]:g} x {WEIGHTS['top_weight']:g})",
                      round(scores[0] * WEIGHTS["top_weight"], 1)))
        rest = sum(scores[1:])
        if rest:
            extra = WEIGHTS["others_max"] * (1 - math.exp(-rest / WEIGHTS["others_scale"]))
            parts.append((f"{len(scores) - 1} more finding(s)", round(extra, 1)))
    for label, points in _hardware_flags(hw_row):
        parts.append((label, points))
    total = sum(p for _l, p in parts)
    if total > 100:
        parts.append(("capped at 100", round(100 - total, 1)))
    return parts


def device_scores(findings, hardware=None):
    """One row per device: risk, band, top finding and the score parts.

    findings must have a 'risk' column (add_finding_scores). hardware: inventory.device_summary() frame
    (optional) providing contract / lifecycle / sw_status per hostname."""
    import numpy as np

    cols = ["hostname", "risk", "risk_band", "top_finding", "top_risk", "scored_findings"]
    scored = findings[findings["risk"] > 0].reset_index(drop=True) if not findings.empty else findings
    if not scored.empty:
        g = scored.groupby("hostname", sort=False)["risk"]
        per = pd.DataFrame({"top_risk": g.max(), "total": g.sum(), "scored_findings": g.size()})
        top_idx = scored.groupby("hostname", sort=False)["risk"].idxmax()
        per["top_finding"] = scored.loc[top_idx.values, "plugin_name"].astype(str).values
    else:
        per = pd.DataFrame(columns=["top_risk", "total", "scored_findings", "top_finding"])
    hosts = pd.Index(pd.unique(pd.concat([findings["hostname"].dropna() if not findings.empty else pd.Series(dtype=str),
                                          hardware["hostname"] if hardware is not None and not hardware.empty
                                          else pd.Series(dtype=str)])))
    out = per.reindex(hosts)
    out["top_risk"] = out["top_risk"].astype(float).fillna(0.0)
    out["total"] = out["total"].astype(float).fillna(0.0)
    out["scored_findings"] = out["scored_findings"].fillna(0).astype(int)
    out["top_finding"] = out["top_finding"].fillna("")
    rest = out["total"] - out["top_risk"]
    score = out["top_risk"] * WEIGHTS["top_weight"] + WEIGHTS["others_max"] * (1 - np.exp(-rest / WEIGHTS["others_scale"]))
    if hardware is not None and not hardware.empty:
        hw = hardware.drop_duplicates("hostname").set_index("hostname").reindex(hosts)
        for column in ("contract", "lifecycle", "sw_status"):
            if column in hw:
                points = hw[column].map(lambda v: WEIGHTS["hardware"].get(v, (None, 0.0))[1] if isinstance(v, str) else 0.0)
                score = score + points.fillna(0.0).astype(float)
    out["risk"] = score.clip(lower=0, upper=100).round(1)
    out["risk_band"] = out["risk"].map(band)
    out = out.reset_index(names="hostname")[cols]
    return out.sort_values("risk", ascending=False, kind="stable").reset_index(drop=True)


def explain_device(hostname, findings, hardware_row=None, now=None):
    """[(label, points)] that add up to the device's score, plus the top finding's own factors."""
    group = findings[findings["hostname"] == hostname] if not findings.empty else findings
    scores = group["risk"].tolist() if not group.empty else []
    parts = _device_parts(scores, hardware_row)
    detail = []
    if not group.empty:
        top = group.sort_values("risk", ascending=False).iloc[0]
        _score, factors = score_finding(top.to_dict(), now)
        detail = [(str(top["plugin_name"]), factors)]
    return parts, detail


def explain_finding(row, now=None):
    score, parts = score_finding(row, now)
    return score, " + ".join(f"{label} ({value:g})" for label, value in parts)


def fleet_summary(device_risk):
    """Headline numbers: device counts per band and a fleet index (mean of the top quartile)."""
    if device_risk.empty:
        return {"index": 0.0, "band": "Low", "counts": {name: 0 for _t, name in BANDS}, "devices": 0}
    scores = device_risk["risk"].sort_values(ascending=False)
    top = scores.head(max(1, math.ceil(len(scores) / 4)))
    index = round(float(top.mean()), 1)
    counts = device_risk["risk_band"].value_counts()
    return {"index": index, "band": band(index), "devices": len(device_risk),
            "counts": {name: int(counts.get(name, 0)) for _t, name in BANDS}}
