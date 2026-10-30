"""Enrichment diagnostics: for every device, how far it got through
AKiPS -> match to Tenable -> model/serial -> Cisco? -> Serial Number to Info / Software Suggestion,
and the first stage where it fell out, in plain words with a hint.
"""

import hashlib
import io
import json
import re
import zipfile
from collections import Counter
from datetime import datetime
from pathlib import Path

import pandas as pd

from tenable_net import cisco, export, inventory

# Stages in pipeline order; the first one a device fails is its "stage".
STAGES = [
    "No hardware inventory",
    "Not matched to AKiPS",
    "AKiPS: no hardware data",
    "AKiPS: no chassis found",
    "Not Cisco",
    "No serial number",
    "Invalid serial",
    "API not enabled",
    "Not looked up yet",
    "Cisco: error",
    "Cisco: no contract record",
    "Software: no suggestion",
    "OK",
]
HINTS = {
    "No hardware inventory": "Run a pull with 'Hardware inventory' ticked (or `python -m tenable_net inventory`).",
    "Not matched to AKiPS": "AKiPS has no device with this IP or name. If it's in AKiPS under another name/IP, add "
                            "a line to device_aliases.csv (akips_device,tenable_hostname). See 'Unmatched AKiPS "
                            "devices' for candidates.",
    "AKiPS: no hardware data": "AKiPS holds no ENTITY-MIB data for this device. Check that AKiPS polls it via SNMP "
                               "and collects inventory; 'Show raw AKiPS data' lists what it has.",
    "AKiPS: no chassis found": "AKiPS has ENTITY-MIB rows but none looked like a chassis with a model or serial. "
                               "'Show raw AKiPS data' and share the entPhysical lines.",
    "Not Cisco": "Only Cisco hardware is sent to Cisco's APIs. If this is Cisco, its sysDescr / model wasn't "
                 "recognised; share the model number.",
    "No serial number": "Neither AKiPS nor Tenable reported a serial, so no contract lookup is possible. "
                        "'Show raw AKiPS data' shows where (or whether) AKiPS stores it.",
    "Invalid serial": "The serial contains characters Cisco serials never have; it was not sent.",
    "API not enabled": "Tick the API under Settings -> Cisco (Test connection shows which ones your app has).",
    "Not looked up yet": "Run a pull with 'Cisco enrichment' ticked, or 'Re-query Cisco' for this device.",
    "Cisco: error": "Cisco rejected this serial / product ID. The error text says why.",
    "Cisco: no contract record": "Serial Number to Info has no record for this serial: it isn't linked to your "
                                 "contracts / Smart Account, or Cisco doesn't know it.",
    "Software: no suggestion": "Software Suggestion returned nothing for this model (normal for some products).",
    "OK": "",
}


def _first(*values):
    return next((v for v in values if v), "")


def _member_stage(row, cov_cache, sw_cache, apis):
    """(stage, reason) for one Cisco chassis row; contract path first, then software."""
    serial, model = str(row["serial"] or "").upper(), str(row["model"] or "").upper()
    contract_stage = None
    if "sn2info" not in apis:
        contract_stage = ("API not enabled", "Serial Number to Info is not enabled")
    elif not serial:
        contract_stage = ("No serial number", f"no serial ({row['source']})")
    elif not cisco.valid_serial(serial):
        contract_stage = ("Invalid serial", f"serial {serial!r} is not a valid Cisco serial")
    elif serial not in cov_cache:
        contract_stage = ("Not looked up yet", f"serial {serial} not looked up yet")
    else:
        entry = cov_cache[serial]
        if entry.get("error"):
            return "Cisco: error", f"Serial Number to Info, {serial}: {entry['error']}"
        if not cisco.has_data(entry):
            return "Cisco: no contract record", f"Serial Number to Info has no record for {serial}"
    if contract_stage and contract_stage[0] != "API not enabled":
        return contract_stage

    if "software" in apis and model:
        cov = cov_cache.get(serial) or {}
        keys = [k for k in (model, str(cov.get("base_pid") or "").upper(), str(cov.get("orderable_pid") or "").upper()) if k]
        entries = [sw_cache[k] for k in keys if k in sw_cache]
        if not entries:
            return "Not looked up yet", f"software suggestions for {model} not looked up yet"
        if any(e.get("error") for e in entries) and not any(cisco.has_data(e) for e in entries):
            return "Cisco: error", f"Software Suggestion, {model}: {next(e['error'] for e in entries if e.get('error'))}"
        if not any(cisco.suggested_releases(e) for e in entries):
            return "Software: no suggestion", f"no suggested release for {', '.join(keys)}"
    if contract_stage:
        return contract_stage
    return "OK", ""


def _devices_from_rows(rows):
    """Device records rebuilt from chassis rows, for caches written before per-device diagnostics existed
    (the next AKiPS pull stores the full records, including devices that produced no rows)."""
    devices = {}
    for r in rows:
        d = devices.setdefault(r["akips_device"], {
            "akips_device": r["akips_device"], "ip": r.get("ip"), "sys_name": r.get("sys_name"),
            "sys_descr": r.get("sys_descr"), "entities": None, "classes": "", "chassis_rule": "(older cache)",
            "chassis": 0, "with_model": 0, "with_serial": 0, "device_serial": "", "issue": ""})
        d["chassis"] += 1
        d["with_model"] += bool(r.get("model"))
        d["with_serial"] += bool(r.get("serial"))
    for d in devices.values():
        if not d["with_serial"]:
            d["issue"] = "AKiPS returned no serial number"
    return list(devices.values())


def enrichment_report(cache_dir, vulns=None, assets=None):
    """Returns (funnel: dict[str, int], devices: DataFrame, unmatched_akips: DataFrame)."""
    if vulns is None:
        try:
            vulns, assets, _ = export.load_cache(cache_dir)
        except FileNotFoundError:
            vulns, assets = [], []
    assets = assets or []
    akips_payload = inventory._read_payload(cache_dir, inventory.AKIPS_FILE)
    akips_devices = akips_payload.get("devices") or _devices_from_rows(akips_payload.get("rows") or [])
    have_akips = bool(akips_payload)
    tenable_rows, _ = inventory._read(cache_dir, inventory.TENABLE_FILE)
    inv = inventory.load_inventory(cache_dir, vulns, assets)
    cache = cisco.load_cache(cache_dir)
    cov_cache, sw_cache = cache["coverage"], cache.get("software", {})
    apis = cisco.enabled_apis()

    index = inventory.tenable_device_index(vulns, assets)
    matcher = inventory.DeviceMatcher(index, inventory.load_aliases())
    akips_by_host, unmatched = {}, []
    for d in akips_devices:
        host, method = matcher.match(d.get("akips_device"), d.get("ip"), d.get("sys_name"))
        if host:
            akips_by_host.setdefault(host, []).append({**d, "match_method": method})
        else:
            unmatched.append(d)

    inv_hosts = inv["hostname"].tolist() if not inv.empty else []
    hosts = list(dict.fromkeys([d["hostname"] for d in index.values()] + inv_hosts
                               + [d["akips_device"] for d in unmatched]))
    host_ip = {d["hostname"]: ", ".join(sorted(d["ips"])) for d in index.values()}
    unmatched_names = {d["akips_device"] for d in unmatched}
    records = []
    for host in hosts:
        in_tenable = host not in unmatched_names or host in host_ip
        akd = akips_by_host.get(host, []) or [d for d in unmatched if d["akips_device"] == host]
        rows = inv[inv["hostname"] == host] if not inv.empty else inv
        cisco_rows = rows[rows["vendor"] == "Cisco"] if not rows.empty else rows
        rec = {
            "hostname": host,
            "in_tenable": in_tenable,
            "ip": host_ip.get(host) or ", ".join(d.get("ip") or "" for d in akd),
            "akips_device": ", ".join(d["akips_device"] for d in akd),
            "match_method": _first(*(d.get("match_method", "") for d in akd),
                                   *(rows["match_method"].tolist() if not rows.empty else [])),
            "akips_issue": "; ".join(d["issue"] for d in akd if d.get("issue")),
            "akips_classes": "; ".join(d.get("classes", "") for d in akd if d.get("classes")),
            "chassis_rule": ", ".join(d.get("chassis_rule", "") for d in akd),
            "members": len(rows),
            "with_model": int((rows["model"] != "").sum()) if not rows.empty else 0,
            "with_serial": int((rows["serial"] != "").sum()) if not rows.empty else 0,
            "vendor": _first(*(rows["vendor"].tolist() if not rows.empty else [])),
            "vendor_source": _first(*(rows["vendor_source"].tolist() if not rows.empty else [])),
            "sys_descr": _first(*(d.get("sys_descr") for d in akd)),
            "models": ", ".join(dict.fromkeys(m for m in rows["model"] if m)) if not rows.empty else "",
            "serials": ", ".join(s for s in rows["serial"] if s) if not rows.empty else "",
            "source": ", ".join(dict.fromkeys(rows["source"])) if not rows.empty else "",
            "contract": ", ".join(dict.fromkeys(c for c in rows["contract"] if c)) if not rows.empty else "",
            "sw_status": ", ".join(dict.fromkeys(c for c in rows["sw_status"] if c)) if not rows.empty else "",
        }
        if rows.empty:
            if not have_akips and not tenable_rows:
                stage, reason = "No hardware inventory", "no hardware inventory has been pulled"
            elif not have_akips:
                stage, reason = "No hardware inventory", "AKiPS isn't used and Tenable plugin output had no model/serial"
            elif not akd:
                stage, reason = "Not matched to AKiPS", "no AKiPS device with this IP or name"
            elif any("no ENTITY-MIB" in (d.get("issue") or "") for d in akd):
                stage, reason = "AKiPS: no hardware data", rec["akips_issue"]
            else:
                stage, reason = "AKiPS: no chassis found", rec["akips_issue"] or "no chassis entity"
            member_results = []
        elif cisco_rows.empty:
            stage = "Not Cisco"
            reason = f"vendor {rec['vendor']} (from {rec['vendor_source'] or 'nothing'})"
            member_results = []
        else:
            member_results = [(r["member"], *_member_stage(r, cov_cache, sw_cache, apis)) for _, r in cisco_rows.iterrows()]
            worst = min(member_results, key=lambda m: STAGES.index(m[1]))
            stage, reason = worst[1], worst[2]
            bad = sum(1 for m in member_results if m[1] != "OK")
            if bad and len(member_results) > 1:
                reason = f"{reason} ({bad} of {len(member_results)} members)"
        rec.update({
            "stage": stage,
            "reason": reason,
            "hint": HINTS.get(stage, ""),
            "member_detail": "; ".join(f"#{m}: {st}{' - ' + rs if rs else ''}" for m, st, rs in member_results),
        })
        records.append(rec)

    devices = pd.DataFrame(records)
    if devices.empty:
        devices = pd.DataFrame(columns=["hostname", "stage", "reason", "hint"])
    tenable = devices[devices["in_tenable"]] if "in_tenable" in devices else devices
    cisco_dev = tenable[tenable.get("vendor", pd.Series(dtype=str)) == "Cisco"] if not tenable.empty else tenable
    funnel = {
        "Tenable devices": len(tenable),
        "with hardware inventory": int((tenable["members"] > 0).sum()) if not tenable.empty else 0,
        "with a model": int((tenable["with_model"] > 0).sum()) if not tenable.empty else 0,
        "with a serial": int((tenable["with_serial"] > 0).sum()) if not tenable.empty else 0,
        "identified as Cisco": len(cisco_dev),
        "Cisco, fully enriched": int((cisco_dev["stage"] == "OK").sum()) if not cisco_dev.empty else 0,
        "AKiPS devices not matched to Tenable": len(unmatched),
    }
    unmatched_df = pd.DataFrame(unmatched, columns=["akips_device", "ip", "sys_name", "sys_descr", "chassis",
                                                    "with_serial", "issue"])
    return funnel, devices, unmatched_df


def stage_counts(devices):
    counts = Counter(devices["stage"]) if not devices.empty else Counter()
    return pd.DataFrame([(s, counts[s], HINTS.get(s, "")) for s in STAGES if counts.get(s)],
                        columns=["stage", "devices", "hint"])


def last_run(cache_dir):
    return cisco.load_cache(cache_dir).get("last_run") or {}


# ---- shareable, scrubbed export ---------------------------------------------------

SENSITIVE_COLUMNS = ("hostname", "ip", "akips_device", "serials", "sys_name", "device_serial", "member_detail",
                     "reason", "sys_descr")
IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def _token(kind, value):
    return f"{kind}-{hashlib.sha256(str(value).encode()).hexdigest()[:8]}"


class Scrubber:
    """Replace hostnames, IPs and serials with stable tokens so a report can be shared."""

    def __init__(self, devices, unmatched):
        self.map = {}
        for col, kind in (("hostname", "host"), ("akips_device", "host")):
            for frame in (devices, unmatched):
                if col in frame:
                    for value in frame[col].dropna():
                        for part in str(value).split(", "):
                            if part:
                                self.map[part] = _token(kind, part.lower())
        for frame in (devices, unmatched):
            for col in ("serials", "device_serial"):
                if col in frame:
                    for value in frame[col].dropna():
                        for part in str(value).split(", "):
                            if part:
                                self.map[part] = _token("sn", part.upper())
        self._rx = re.compile("|".join(re.escape(k) for k in sorted(self.map, key=len, reverse=True))) if self.map else None

    def text(self, value):
        if not isinstance(value, str):
            return value
        if self._rx:
            value = self._rx.sub(lambda m: self.map[m.group(0)], value)
        return IP_RE.sub(lambda m: _token("ip", m.group(0)), value)

    def frame(self, df):
        df = df.copy()
        for col in df.columns:  # pandas 3 stores text as a string dtype, older versions as object
            if df[col].dtype == object or pd.api.types.is_string_dtype(df[col]):
                df[col] = df[col].map(self.text)
        return df


def export_bundle(cache_dir, path, scrub=True):
    """Zip with diagnostics CSVs, AKiPS device records, Cisco last-run info and raw samples."""
    funnel, devices, unmatched = enrichment_report(cache_dir)
    akips_devices = pd.DataFrame(inventory._read_payload(cache_dir, inventory.AKIPS_FILE).get("devices") or [])
    scrubber = Scrubber(devices, pd.concat([unmatched, akips_devices], ignore_index=True)) if scrub else None
    out = scrubber.frame if scrubber else (lambda df: df)
    txt = scrubber.text if scrubber else (lambda t: t)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("README.txt", "tenable_net enrichment diagnostics\n"
                    f"created {datetime.now():%Y-%m-%d %H:%M}\nscrubbed: {bool(scrub)}\n"
                    + "".join(f"{k}: {v}\n" for k, v in funnel.items()))
        zf.writestr("devices.csv", out(devices).to_csv(index=False))
        zf.writestr("stages.csv", stage_counts(devices).to_csv(index=False))
        zf.writestr("unmatched_akips_devices.csv", out(unmatched).to_csv(index=False))
        zf.writestr("akips_devices.csv", out(akips_devices).to_csv(index=False))
        zf.writestr("cisco_last_run.json", txt(json.dumps(last_run(cache_dir), indent=1)))
        samples = Path(cache_dir) / inventory.SAMPLES_DIR
        if samples.exists():
            for f in sorted(samples.iterdir()):
                if f.is_file() and f.stat().st_size < 5_000_000:
                    zf.writestr(f"samples/{txt(f.name)}", txt(f.read_text(errors="replace")))
    Path(path).write_bytes(buf.getvalue())
    return Path(path)
