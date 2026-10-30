"""Flatten nested Tenable export records into pandas DataFrames.

Export fields vary by plugin and asset type, so every lookup is defensive.
"""

import re

import pandas as pd

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

FINDING_COLUMNS = [
    "hostname", "ip", "os", "asset_uuid",
    "plugin_id", "plugin_name", "plugin_family", "severity", "vpr", "cvss3",
    "cves", "exploit_available", "state", "port", "protocol", "service",
    "first_found", "last_found", "synopsis", "solution", "see_also", "output",
]


def _first(value):
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _join(value):
    if isinstance(value, list):
        return ", ".join(str(v) for v in value if v)
    return value or ""


def _hostname(asset):
    return (
        asset.get("hostname")
        or asset.get("fqdn")
        or asset.get("netbios_name")
        or asset.get("ipv4")
        or asset.get("uuid")
    )


def finding_row(rec):
    asset = rec.get("asset") or {}
    plugin = rec.get("plugin") or {}
    port = rec.get("port") or {}
    vpr = plugin.get("vpr") or {}
    return {
        "hostname": _hostname(asset),
        "ip": asset.get("ipv4") or asset.get("ipv6"),
        "os": _join(asset.get("operating_system")),
        "asset_uuid": asset.get("uuid"),
        "plugin_id": plugin.get("id"),
        "plugin_name": plugin.get("name"),
        "plugin_family": plugin.get("family"),
        "severity": (rec.get("severity") or "").lower(),
        "vpr": vpr.get("score"),
        "cvss3": plugin.get("cvss3_base_score"),
        "cves": _join(plugin.get("cve")),
        "exploit_available": plugin.get("exploit_available"),
        "state": (rec.get("state") or "").upper(),
        "port": port.get("port"),
        "protocol": port.get("protocol"),
        "service": port.get("service"),
        "first_found": rec.get("first_found"),
        "last_found": rec.get("last_found"),
        "synopsis": plugin.get("synopsis"),
        "solution": plugin.get("solution"),
        "see_also": _join(plugin.get("see_also")),
        "output": rec.get("output"),
    }


def findings_frame(vulns, include_info=False):
    """One row per finding (device x plugin x port)."""
    df = pd.DataFrame([finding_row(r) for r in vulns], columns=FINDING_COLUMNS)
    if not include_info:
        df = df[df["severity"] != "info"]
    for col in ("first_found", "last_found"):
        df[col] = pd.to_datetime(df[col], errors="coerce", utc=True)
    df["vpr"] = pd.to_numeric(df["vpr"], errors="coerce")
    df["cvss3"] = pd.to_numeric(df["cvss3"], errors="coerce")
    df["severity"] = pd.Categorical(df["severity"], categories=SEVERITY_ORDER, ordered=True)
    return df.sort_values(["severity", "vpr", "hostname"], ascending=[True, False, True]).reset_index(drop=True)


def assets_frame(assets):
    """One row per asset from the asset export."""
    rows = []
    for a in assets:
        rows.append({
            "hostname": _first(a.get("hostnames")) or _first(a.get("fqdns")) or _first(a.get("ipv4s")),
            "ip": _join(a.get("ipv4s")),
            "os": _join(a.get("operating_systems")),
            "system_type": _join(a.get("system_types")),
            "tags": _join([f"{t.get('key')}:{t.get('value')}" for t in a.get("tags") or []]),
            "last_seen": a.get("last_seen"),
            "last_authenticated_scan": a.get("last_authenticated_scan_date"),
            "asset_uuid": a.get("id"),
        })
    df = pd.DataFrame(rows, columns=[
        "hostname", "ip", "os", "system_type", "tags", "last_seen", "last_authenticated_scan", "asset_uuid",
    ])
    for col in ("last_seen", "last_authenticated_scan"):
        df[col] = pd.to_datetime(df[col], errors="coerce", utc=True)
    return df


# Checked in order; each pattern is matched on word boundaries so e.g. "ios" doesn't hit "FortiOS".
VENDOR_PATTERNS = [
    (r"meraki", "Cisco Meraki"),
    (r"fortios|fortinet|fortigate", "Fortinet"),
    (r"cisco|ios(-| )?xe|ios(-| )?xr|ios|nx-os|asa", "Cisco"),
    (r"junos|juniper", "Juniper"),
    (r"pan-os|palo alto", "Palo Alto"),
    (r"arista|eos", "Arista"),
    (r"arubaos|aruba|aos-cx", "Aruba"),
    (r"big-ip|f5", "F5"),
    (r"check ?point|gaia", "Check Point"),
    (r"procurve|comware|hpe", "HPE"),
    (r"linux", "Linux"),
    (r"windows", "Windows"),
]
_VENDOR_RES = [(re.compile(rf"\b(?:{pattern})\b"), vendor) for pattern, vendor in VENDOR_PATTERNS]


def vendor_of(os_string):
    """Best-effort vendor bucket from an OS string, for network gear."""
    s = (os_string or "").lower()
    if not s:
        return "Unknown"
    for regex, vendor in _VENDOR_RES:
        if regex.search(s):
            return vendor
    return "Other"
