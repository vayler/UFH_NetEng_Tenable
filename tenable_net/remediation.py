"""Remediation planner: group findings into concrete actions and rank them.

Action types
  OS upgrade     vendor OS advisories (Cisco IOS/IOS XE/NX-OS, Junos, PAN-OS, FortiOS, ...) grouped by
                 vendor + model; the target is Cisco's suggested release when known. "Confirmed" when every
                 advisory's fixed release (from plugin output) is at or below the target, else "Likely".
  Configuration  everything else, grouped by plugin (e.g. weak SSH ciphers on 23 devices).
  Hardware       renew support contracts, replace hardware past / near Last Date of Support.

Ranking: priority = risk removed / sqrt(devices touched). Risk removed is the sum of the risk scores of
the findings the action closes (hardware actions use the device-score points they carry), so a fix that
closes many severe findings on few devices comes first, without ignoring fleet-wide one-liners.
"""

import math
import re

import pandas as pd

from tenable_net import risk
from tenable_net.inventory import version_key

OS_FAMILY_RE = re.compile(
    r"\b(cisco|junos|juniper|palo alto|pan-os|fortinet|fortios|firewalls|f5|big-ip|arista|aruba|huawei|"
    r"sonicwall|check ?point|mikrotik)\b", re.I)
OS_NAME_RE = re.compile(
    r"^(cisco (ios|ios xe|ios xr|nx-os|asa|firepower)|juniper junos|palo alto networks pan-os|fortinet fortios|"
    r"arista (networks )?eos|aruba ?os|f5 networks big-ip)", re.I)
FIXED_RE = re.compile(r"fixed (?:release|version|in)\s*[:=]?\s*([0-9][\w.()\-]*)", re.I)
ACTION_COLUMNS = ["id", "type", "title", "target", "confidence", "devices", "findings", "critical", "high",
                  "risk_removed", "priority", "vendor", "detail"]


def is_os_advisory(row):
    family = str(row.get("plugin_family") or "")
    name = str(row.get("plugin_name") or "")
    return bool(OS_NAME_RE.search(name) or ("local security checks" in family.lower() and OS_FAMILY_RE.search(family))
                or family.upper() == "CISCO")


def fixed_versions(output):
    return FIXED_RE.findall(output) if isinstance(output, str) else []


def _versions(values):
    """Distinct releases (17.12.04 and 17.12.4 count once), oldest first."""
    seen = {}
    for value in values:
        for v in str(value or "").split(","):
            v = v.strip()
            if v and tuple(version_key(v)) not in seen:
                seen[tuple(version_key(v))] = v
    return [seen[k] for k in sorted(seen)]


def _sev_counts(group):
    sev = group["severity"].astype(str)
    return int((sev == "critical").sum()), int((sev == "high").sum())


def plan(findings, inventory=None, device_risk=None):
    """(actions DataFrame ranked by priority, {action id: findings/devices frame for that action})."""
    f = findings[(findings["severity"].astype(str) != "info")].copy()
    if "risk" not in f:
        f = risk.add_finding_scores(f)
    f = f[f["risk"] > 0]
    hw = {}
    if inventory is not None and not inventory.empty:
        for host, g in inventory.groupby("hostname"):
            models = [m for m in g["model"] if m]
            hw[host] = {
                "model": models[0] if models else "",
                "running": ", ".join(dict.fromkeys(v for v in g["sw_version"] if v)),
                "suggested": [r.strip() for r in str(g["recommended_sw"].dropna().iloc[0]).split(",")]
                if g["recommended_sw"].notna().any() else [],
                "contract": ", ".join(dict.fromkeys(c for c in g["contract"] if c)),
                "lifecycle": ", ".join(dict.fromkeys(c for c in g["lifecycle"] if c)),
                "ldos": g["ldos"].min() if "ldos" in g else None,
            }
    actions, members = [], {}

    def add(kind, title, group, target="", confidence="", vendor="", detail="", risk_removed=None):
        aid = f"{kind[:2].upper()}{len(actions) + 1:03d}"
        crit, high = _sev_counts(group) if "severity" in group else (0, 0)
        devices = int(group["hostname"].nunique())
        removed = float(group["risk"].sum()) if risk_removed is None else float(risk_removed)
        actions.append({
            "id": aid, "type": kind, "title": title, "target": target, "confidence": confidence,
            "devices": devices, "findings": int(len(group)) if "plugin_id" in group else 0,
            "critical": crit, "high": high, "risk_removed": round(removed, 1),
            "priority": round(removed / math.sqrt(max(devices, 1)), 1), "vendor": vendor, "detail": detail,
        })
        members[aid] = group

    # 1. OS upgrades: vendor advisories grouped by vendor + model
    os_mask = f.apply(is_os_advisory, axis=1) if not f.empty else pd.Series(dtype=bool)
    os_findings = f[os_mask] if not f.empty else f
    if not os_findings.empty:
        os_findings = os_findings.assign(
            model=[hw.get(h, {}).get("model") or "" for h in os_findings["hostname"]],
            running=[hw.get(h, {}).get("running") or "" for h in os_findings["hostname"]])
        os_findings["group_key"] = [m or o for m, o in zip(os_findings["model"], os_findings["os"])]
        for (vendor, key), g in os_findings.groupby(["vendor", "group_key"], sort=False):
            suggested = next((hw[h]["suggested"] for h in g["hostname"] if hw.get(h, {}).get("suggested")), [])
            target = max(suggested, key=version_key) if suggested else ""
            fixes = [v for out in g.get("output", pd.Series(dtype=object)) for v in fixed_versions(out)]
            if target and fixes:
                confidence = "Confirmed" if all(version_key(v) <= version_key(target) for v in fixes) else "Check"
            else:
                confidence = "Likely" if target else "Find release"
            running = ", ".join(_versions(g["running"]))[:80]
            title = (f"Upgrade {g['hostname'].nunique()} × {key}" + (f" to {target}" if target else "")
                     + (f" (running {running})" if running else ""))
            detail = ("Cisco's suggested release closes these advisories (fixed releases from plugin output are at or "
                      "below it)." if confidence == "Confirmed" else
                      "Cisco suggests this release; check each advisory's fixed release before scheduling."
                      if confidence in ("Likely", "Check") else
                      "Vendor OS advisories: pick a release that fixes all of them (see each finding's solution).")
            add("OS upgrade", title, g, target=target, confidence=confidence, vendor=str(vendor), detail=detail)

    # 2. configuration / hardening, grouped by plugin
    rest = f[~os_mask] if not f.empty else f
    for (pid, _name), g in rest.groupby(["plugin_id", "plugin_name"], sort=False) if not rest.empty else []:
        first = g.iloc[0]
        n = g["hostname"].nunique()
        add("Configuration", f"Fix on {n} device{'s' if n != 1 else ''}: {first['plugin_name']}", g,
            vendor=", ".join(sorted(set(g["vendor"].dropna())))[:60],
            detail=str(first.get("solution") or "")[:600], confidence="")

    # 3. hardware lifecycle / contracts
    hardware_points = {k: v[1] for k, v in risk.WEIGHTS["hardware"].items()}
    for label, test, points_key, detail in (
        ("Renew support contract", lambda h: "Not covered" in h["contract"], "Not covered",
         "Hardware not under Cisco contract: no TAC support or software entitlement for fixes."),
        ("Replace hardware past Last Date of Support", lambda h: "Past LDoS" in h["lifecycle"], "Past LDoS",
         "Cisco no longer publishes fixes for this hardware: vulnerabilities found later will stay open."),
        ("Plan replacement: LDoS within 12 months", lambda h: "LDoS < 12 mo" in h["lifecycle"], "LDoS < 12 mo",
         "Support ends within a year; budget and schedule replacements now."),
    ):
        hosts = [h for h, info in hw.items() if test(info)]
        if hosts:
            g = pd.DataFrame({"hostname": hosts, "model": [hw[h]["model"] for h in hosts],
                              "running": [hw[h]["running"] for h in hosts],
                              "contract": [hw[h]["contract"] for h in hosts],
                              "lifecycle": [hw[h]["lifecycle"] for h in hosts]})
            add("Hardware", f"{label} ({len(hosts)} devices)", g, detail=detail,
                risk_removed=hardware_points[points_key] * len(hosts))

    out = pd.DataFrame(actions, columns=ACTION_COLUMNS)
    out = out.sort_values(["priority", "critical"], ascending=False).reset_index(drop=True)
    out.insert(0, "rank", range(1, len(out) + 1))
    return out, members


def action_items(action, group):
    """Per-device rows for an action (for the detail table and change-ticket export)."""
    if group.empty:
        return group
    if "plugin_id" not in group:  # hardware action: already one row per device
        return group.reset_index(drop=True)
    agg = group.groupby("hostname").agg(
        ip=("ip", "first"), model=("model", "first") if "model" in group else ("os", "first"),
        running=("running", "first") if "running" in group else ("os", "first"),
        findings=("plugin_id", "count"), worst=("severity", "min"), risk=("risk", "max"),
        plugins=("plugin_id", lambda s: ", ".join(str(p) for p in sorted(set(s)))),
        cves=("cves", lambda s: ", ".join(sorted({c for v in s.dropna() for c in str(v).split(", ") if c}))[:300]),
    ).reset_index()
    agg.insert(1, "target", action.get("target") or "")
    return agg.sort_values("risk", ascending=False).reset_index(drop=True)
