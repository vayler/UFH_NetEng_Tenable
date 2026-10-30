"""Hardware inventory: chassis/stack-member model + serial from AKiPS (primary) and Tenable
plugin output (fallback), matched to Tenable devices and enriched with Cisco lifecycle/contract.

Raw source data is cached separately (akips_inventory.json, tenable_inventory.json, cisco.json)
and joined at load time, so the join always reflects the latest vuln/asset pull.
"""

import json
import re
from datetime import date, datetime, timezone
from pathlib import Path

import pandas as pd

from tenable_net import akips, cisco, export, normalize

AKIPS_FILE = "akips_inventory.json"
TENABLE_FILE = "tenable_inventory.json"
SAMPLES_DIR = "samples"

# Tenable plugins whose output carries model / serial for Cisco gear (credentialed SSH scans).
INVENTORY_PLUGINS = {
    67217: "Cisco IOS XE Version",
    47864: "Cisco IOS Version",
}

INVENTORY_COLUMNS = [
    "hostname", "in_tenable", "akips_device", "ip", "vendor", "member", "model", "serial", "sw_version", "source",
]
CISCO_COLUMNS = [
    "contract", "contract_end", "service_level", "orderable_pid", "lifecycle", "end_of_sale",
    "end_of_sw_maint", "ldos", "migration_pid", "bulletin_url",
]
LIFECYCLE_RANK = ["Past LDoS", "LDoS < 12 mo", "End of sale", "EoX announced", "Current", "Unknown", ""]


# ---- Tenable plugin output ----------------------------------------------------

KV_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9 /_()-]*?)\s*:\s*(\S.*?)\s*$", re.M)
MODEL_KEYS = {"model", "model number", "model name", "hardware", "platform", "product id", "pid"}
SERIAL_KEYS = {"serial", "serial number", "serial numbers", "system serial number", "processor board id", "sn"}
VERSION_KEYS = {"version", "software version", "ios version", "ios-xe version"}
RAW_PATTERNS = {
    "model": [re.compile(r"^\s*Model [Nn]umber\s*:\s*(\S+)", re.M),
              re.compile(r"^cisco\s+(\S+)\s+\(.*\)\s+processor", re.M | re.I)],
    "serial": [re.compile(r"^\s*System [Ss]erial [Nn]umber\s*:\s*(\S+)", re.M),
               re.compile(r"Processor board ID\s+(\S+)", re.I)],
}


def _clean_serial(value):
    value = (value or "").strip().strip(",")
    return "" if value.lower() in {"", "n/a", "na", "unknown", "none", "0", "-"} else value


def parse_plugin_output(text):
    """Return a list of {model, serial, sw_version} found in one plugin output (several for stacks)."""
    if not isinstance(text, str) or not text.strip():
        return []
    models, serials, version = [], [], ""
    for key, value in KV_RE.findall(text):
        k = key.strip().lower()
        if k in MODEL_KEYS:
            models.append(value.split()[0])
        elif k in SERIAL_KEYS:
            serials.extend(s for s in re.split(r"[,\s]+", value) if _clean_serial(s))
        elif k in VERSION_KEYS and not version:
            version = value
    if not models:
        for rx in RAW_PATTERNS["model"]:
            models.extend(rx.findall(text))
    if not serials:
        for rx in RAW_PATTERNS["serial"]:
            serials.extend(s for s in rx.findall(text) if _clean_serial(s))
    serials = list(dict.fromkeys(serials))  # de-dupe, keep order
    models = list(dict.fromkeys(models))
    if not models and not serials:
        return []
    count = max(len(models), len(serials), 1)
    return [
        {
            "model": models[i] if i < len(models) else (models[0] if len(models) == 1 else ""),
            "serial": serials[i] if i < len(serials) else "",
            "sw_version": version,
        }
        for i in range(count)
    ]


def parse_tenable_inventory(records):
    """One row per chassis found in Tenable inventory-plugin output."""
    best = {}
    for rec in records:
        asset = rec.get("asset") or {}
        plugin_id = (rec.get("plugin") or {}).get("id")
        members = parse_plugin_output(rec.get("output"))
        uuid = asset.get("uuid")
        if not members or not uuid:
            continue
        # Prefer the plugin that found the most serials for this asset.
        score = sum(1 for m in members if m["serial"])
        if uuid in best and best[uuid][0] >= score:
            continue
        best[uuid] = (score, [
            {
                "asset_uuid": uuid,
                "hostname": normalize._hostname(asset),
                "ip": asset.get("ipv4"),
                "member": i,
                "plugin_id": plugin_id,
                **m,
            }
            for i, m in enumerate(members, start=1)
        ])
    return [row for _score, rows in best.values() for row in rows]


# ---- matching AKiPS devices to Tenable devices ---------------------------------

def _short(name):
    return str(name or "").strip().lower().split(".")[0]


def tenable_device_index(vulns, assets):
    """{asset_uuid: {hostname (as shown in the app), ips, names}} from vuln + asset exports."""
    index = {}
    for rec in vulns:
        a = rec.get("asset") or {}
        uuid = a.get("uuid")
        if not uuid or uuid in index:
            continue
        index[uuid] = {
            "hostname": normalize._hostname(a),
            "ips": {a.get("ipv4")} - {None},
            "names": {_short(a.get(k)) for k in ("hostname", "fqdn", "netbios_name") if a.get(k)},
        }
    for a in assets:
        uuid = a.get("id")
        if not uuid:
            continue
        entry = index.setdefault(uuid, {
            "hostname": normalize.assets_frame([a]).iloc[0]["hostname"],
            "ips": set(), "names": set(),
        })
        entry["ips"] |= set(a.get("ipv4s") or [])
        entry["names"] |= {_short(n) for n in (a.get("hostnames") or []) + (a.get("fqdns") or [])}
    return index


def build_inventory(akips_rows, tenable_rows, device_index):
    """Join sources into one row per chassis/stack member. AKiPS wins; Tenable fills gaps."""
    by_ip, by_name = {}, {}
    for uuid, d in device_index.items():
        for ip in d["ips"]:
            by_ip.setdefault(ip, d["hostname"])
        for name in d["names"]:
            by_name.setdefault(name, d["hostname"])

    rows = []
    akips_hosts = set()
    for r in akips_rows:
        host = by_ip.get(r.get("ip")) or by_name.get(_short(r.get("akips_device")))
        if host:
            akips_hosts.add(host)
        rows.append({
            "hostname": host or r.get("akips_device"),
            "in_tenable": bool(host),
            "akips_device": r.get("akips_device"),
            "ip": r.get("ip"),
            "vendor": normalize.vendor_of(r.get("sys_descr")),
            "member": r.get("member"),
            "model": r.get("model") or "",
            "serial": r.get("serial") or "",
            "sw_version": r.get("sw_version") or "",
            "source": "AKiPS",
        })

    for r in tenable_rows:
        if r["hostname"] in akips_hosts:
            continue
        rows.append({
            "hostname": r["hostname"],
            "in_tenable": True,
            "akips_device": None,
            "ip": r.get("ip"),
            "vendor": "Cisco",  # only Cisco version plugins are parsed
            "member": r.get("member"),
            "model": r.get("model") or "",
            "serial": r.get("serial") or "",
            "sw_version": r.get("sw_version") or "",
            "source": f"Tenable {r.get('plugin_id')}",
        })
    df = pd.DataFrame(rows, columns=INVENTORY_COLUMNS)
    return df.sort_values(["hostname", "member"], na_position="last").reset_index(drop=True)


# ---- Cisco enrichment -----------------------------------------------------------

def _to_date(value):
    if not value:
        return None
    try:
        return date.fromisoformat(str(value)[:10])
    except ValueError:
        return None


def lifecycle_status(eox, today=None):
    today = today or date.today()
    if not eox:
        return "Unknown"
    ldos, eos = _to_date(eox.get("ldos")), _to_date(eox.get("end_of_sale"))
    if ldos and ldos < today:
        return "Past LDoS"
    if ldos and (ldos - today).days <= 365:
        return "LDoS < 12 mo"
    if eos and eos < today:
        return "End of sale"
    if eox.get("eox_status") == "Announced":
        return "EoX announced"
    if eox.get("eox_status") == "No EoX announced":
        return "Current"
    return "Unknown"


def cisco_keys(inv):
    """(serials, product IDs) to look up, for Cisco hardware only."""
    cisco_rows = inv[inv["vendor"] == "Cisco"]
    serials = sorted({s for s in cisco_rows["serial"] if s})
    pids = sorted({m for m in cisco_rows["model"] if m})
    return serials, pids


def enrich(inv, cisco_cache, today=None):
    """Add contract + lifecycle columns from the Cisco cache (no network)."""
    inv = inv.copy()
    for col in CISCO_COLUMNS:
        inv[col] = None
    if inv.empty:
        return inv
    cov_cache, sn_cache, pid_cache = cisco_cache["coverage"], cisco_cache["eox_serial"], cisco_cache["eox_pid"]
    records = []
    for _, row in inv.iterrows():
        serial, model = str(row["serial"]).upper(), str(row["model"]).upper()
        if row["vendor"] != "Cisco":
            records.append({c: None for c in CISCO_COLUMNS} | {"contract": "", "lifecycle": ""})
            continue
        cov = cov_cache.get(serial) if serial else None
        eox = sn_cache.get(serial) if serial else None
        if not (eox and (eox.get("ldos") or eox.get("end_of_sale"))):
            pid = ((cov or {}).get("orderable_pid") or model).upper()
            eox = pid_cache.get(pid) or pid_cache.get(model) or eox
        if cov and cov.get("covered") is True:
            contract = "Covered"
        elif cov and cov.get("covered") is False:
            contract = "Not covered"
        else:
            contract = "Unknown"
        eox = eox or {}
        records.append({
            "contract": contract,
            "contract_end": (cov or {}).get("contract_end"),
            "service_level": (cov or {}).get("service_level"),
            "orderable_pid": (cov or {}).get("orderable_pid"),
            "lifecycle": lifecycle_status(eox, today),
            "end_of_sale": eox.get("end_of_sale"),
            "end_of_sw_maint": eox.get("end_of_sw_maint"),
            "ldos": eox.get("ldos"),
            "migration_pid": eox.get("migration_pid"),
            "bulletin_url": eox.get("bulletin_url"),
        })
    extra = pd.DataFrame(records, index=inv.index)
    for col in CISCO_COLUMNS:
        inv[col] = extra[col]
    for col in ("contract_end", "end_of_sale", "end_of_sw_maint", "ldos"):
        inv[col] = pd.to_datetime(inv[col], errors="coerce")
    return inv


def device_summary(inv):
    """One row per hostname: models, serial count, worst lifecycle, earliest LDoS, contract status."""
    cols = ["hostname", "model", "members", "serials", "lifecycle", "ldos", "end_of_sale", "contract",
            "contract_end", "in_tenable"]
    if inv is None or inv.empty:
        return pd.DataFrame(columns=cols)

    def worst(values):
        present = [v for v in values if isinstance(v, str)]
        return min(present, key=lambda v: LIFECYCLE_RANK.index(v) if v in LIFECYCLE_RANK else 99) if present else ""

    def contract(values):
        values = [v for v in values if v]
        if not values:
            return ""
        if "Not covered" in values:
            return "Not covered"
        return "Covered" if all(v == "Covered" for v in values) else "Unknown"

    grouped = inv.groupby("hostname", sort=False)
    out = pd.DataFrame({
        "model": grouped["model"].agg(lambda s: ", ".join(dict.fromkeys(m for m in s if m))),
        "members": grouped.size(),
        "serials": grouped["serial"].agg(lambda s: ", ".join(x for x in s if x)),
        "lifecycle": grouped["lifecycle"].agg(worst),
        "ldos": grouped["ldos"].min(),
        "end_of_sale": grouped["end_of_sale"].min(),
        "contract": grouped["contract"].agg(contract),
        "contract_end": grouped["contract_end"].min(),
        "in_tenable": grouped["in_tenable"].any(),
    }).reset_index()
    return out[cols]


# ---- cache + refresh ---------------------------------------------------------------

def _write(cache_dir, name, rows):
    Path(cache_dir).mkdir(parents=True, exist_ok=True)
    payload = {"fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "rows": rows}
    (Path(cache_dir) / name).write_text(json.dumps(payload, default=str))


def _read(cache_dir, name):
    path = Path(cache_dir) / name
    if not path.exists():
        return [], None
    payload = json.loads(path.read_text())
    return payload.get("rows", []), payload.get("fetched_at")


def has_cache(cache_dir):
    return any((Path(cache_dir) / n).exists() for n in (AKIPS_FILE, TENABLE_FILE))


def export_tenable_inventory(tio, progress=None, cancelled=None):
    return export._collect(
        tio.exports.vulns(plugin_id=list(INVENTORY_PLUGINS), severity=["info"], include_plugin_output=True),
        progress, cancelled,
    )


def dump_samples(cache_dir, akips_raw=None, tenable_records=None, n=3):
    """Write a few raw records from each source to cache/samples/ for checking parsers. Scrub before sharing."""
    out = Path(cache_dir) / SAMPLES_DIR
    out.mkdir(parents=True, exist_ok=True)
    written = []
    if akips_raw:
        path = out / "akips_raw.txt"
        path.write_text("\n\n".join(
            f"### {cmd}\n" + "\n".join(text.splitlines()[: n * 10]) for cmd, text in akips_raw.items()))
        written.append(path)
    if tenable_records:
        path = out / "tenable_inventory_sample.json"
        path.write_text(json.dumps(tenable_records[:n], indent=1, default=str))
        written.append(path)
    return written


def refresh(cache_dir, tio=None, akips_client=None, log=None, progress=None, cancelled=None, samples=0):
    """Fetch inventory from whichever sources are given and cache them. Returns a summary dict."""
    log = log or (lambda msg: None)
    summary = {}
    akips_raw = None
    if akips_client is not None:
        log("Fetching hardware inventory from AKiPS ...")
        akips_raw = akips_client.raw_responses()
        rows = akips.rows_from_raw(akips_raw)
        _write(cache_dir, AKIPS_FILE, rows)
        summary["akips_chassis"] = len(rows)
        log(f"  AKiPS: {len(rows)} chassis/stack members.")
    tenable_records = None
    if tio is not None:
        log(f"Exporting Tenable inventory plugins {sorted(INVENTORY_PLUGINS)} ...")
        tenable_records = export_tenable_inventory(
            tio, progress=progress and (lambda n: progress("inventory", n)), cancelled=cancelled)
        rows = parse_tenable_inventory(tenable_records)
        _write(cache_dir, TENABLE_FILE, rows)
        summary["tenable_chassis"] = len(rows)
        log(f"  Tenable: {len(tenable_records)} plugin results, {len(rows)} chassis parsed.")
    if samples:
        for path in dump_samples(cache_dir, akips_raw, tenable_records, samples):
            log(f"  sample written: {path}")
    return summary


def load_inventory(cache_dir, vulns=None, assets=None, today=None):
    """Joined + Cisco-enriched inventory DataFrame (empty if no inventory has been pulled)."""
    akips_rows, _ = _read(cache_dir, AKIPS_FILE)
    tenable_rows, _ = _read(cache_dir, TENABLE_FILE)
    if not akips_rows and not tenable_rows:
        return enrich(pd.DataFrame(columns=INVENTORY_COLUMNS), cisco.load_cache(cache_dir))
    if vulns is None:
        try:
            vulns, assets, _ = export.load_cache(cache_dir)
        except FileNotFoundError:  # inventory pulled before any vuln pull
            vulns, assets = [], []
    inv = build_inventory(akips_rows, tenable_rows, tenable_device_index(vulns, assets or []))
    return enrich(inv, cisco.load_cache(cache_dir), today)


def refresh_cisco(cache_dir, cisco_client, force=False, log=None):
    inv = load_inventory(cache_dir)
    serials, pids = cisco_keys(inv)
    log = log or (lambda msg: None)
    log(f"Cisco lookups for {len(serials)} serials / {len(pids)} product IDs ...")
    cisco.refresh(cisco_client, serials, pids, cache_dir, force=force, log=log)
    return len(serials), len(pids)


def refresh_all(cache_dir, tio=None, akips_client=None, cisco_client=None, force_cisco=False, strict=True,
                log=None, progress=None, cancelled=None, samples=0):
    """Inventory refresh (AKiPS + Tenable), then Cisco enrichment. Used by the CLI and the GUI.

    With strict=False a failing source is logged as a warning and skipped, so a vuln pull that
    asked for inventory as an extra never fails because AKiPS or Cisco was unreachable.
    """
    log = log or (lambda msg: None)

    def step(label, fn):
        try:
            return fn()
        except export.ExportCancelled:
            raise
        except Exception as exc:
            if strict:
                raise
            log(f"[yellow]WARNING: {label} skipped: {type(exc).__name__}: {exc}[/yellow]")

    if akips_client is not None:
        step("AKiPS inventory", lambda: refresh(cache_dir, akips_client=akips_client, log=log, samples=samples))
    if tio is not None:
        step("Tenable inventory", lambda: refresh(cache_dir, tio=tio, log=log, progress=progress,
                                                  cancelled=cancelled, samples=samples))
    if cisco_client is not None:
        step("Cisco lookups", lambda: refresh_cisco(cache_dir, cisco_client, force=force_cisco, log=log))
