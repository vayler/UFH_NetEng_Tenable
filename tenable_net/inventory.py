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
    "match_method", "vendor_source",
]
ALIASES_FILE = "device_aliases.csv"
GENERIC_VENDORS = {"Unknown", "Other", "Linux", "Windows"}
CISCO_COLUMNS = [
    "contract", "contract_end", "contract_number", "service_level", "warranty_end", "product_line_end",
    "orderable_pid", "recommended_sw", "sw_status", "lifecycle", "end_of_sale", "end_of_sw_maint", "ldos",
    "migration_pid", "bulletin_url",
]
SW_STATUS_RANK = ["Upgrade suggested", "Newer than suggested", "On suggested release", "Suggestion available",
                  "No suggestion", ""]
DATE_COLUMNS = ("contract_end", "warranty_end", "product_line_end", "end_of_sale", "end_of_sw_maint", "ldos")
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
            "os": " ".join(a.get("operating_system") or []),
        }
    for a in assets:
        uuid = a.get("id")
        if not uuid:
            continue
        entry = index.setdefault(uuid, {
            "hostname": normalize.assets_frame([a]).iloc[0]["hostname"],
            "ips": set(), "names": set(), "os": "",
        })
        entry["os"] = entry["os"] or " ".join(a.get("operating_systems") or [])
        entry["ips"] |= set(a.get("ipv4s") or [])
        entry["names"] |= {_short(n) for n in (a.get("hostnames") or []) + (a.get("fqdns") or [])}
    return index


# Cisco product-ID prefixes, for recognising Cisco hardware when sysDescr / OS don't say.
CISCO_PID_RE = re.compile(
    r"^(WS-C|C9\d{2,3}|C8\d{2,3}|C[1-6]\d{3}|N[2-9]K-|N\d{2,4}-|ISR\d|ASR\d|CISCO\d|AIR-|IE-?\d|IR\d|"
    r"CBS\d|SG\d{3}|FPR-?\d|ASA\d|ME-\d|NCS-?\d|CAT\d|CW9|C1000|C1300|UCS[A-Z]?-|SNS-\d|AIR-CT|C9800)", re.I)


def looks_cisco(model):
    return bool(model) and bool(CISCO_PID_RE.match(str(model).strip()))


def infer_vendor_source(sources, model=""):
    """(vendor, where it came from). sources: [(label, text)]. A definite network vendor from any text wins;
    a Cisco-shaped model number beats generic answers like Linux/Windows (ISE, UCS, some WLCs)."""
    generic = None
    for label, text in sources:
        vendor = normalize.vendor_of(text)
        if vendor not in GENERIC_VENDORS:
            return vendor, label
        if vendor != "Unknown" and generic is None:
            generic = (vendor, label)
    if looks_cisco(model):
        return "Cisco", "model number"
    return generic or ("Unknown", "")


def infer_vendor(*texts, model=""):
    return infer_vendor_source([("text", t) for t in texts], model=model)[0]


def aliases_path():
    """device_aliases.csv lives next to .env (the project folder)."""
    from tenable_net.client import env_path

    return Path(env_path()).parent / ALIASES_FILE


def load_aliases(path=None):
    """{short AKiPS device name or sysName: Tenable hostname/IP} from device_aliases.csv (optional).

    Columns: akips_device,tenable_hostname. Lines starting with # are ignored."""
    path = Path(path) if path else aliases_path()
    if not path.exists():
        return {}
    aliases = {}
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 2 or not parts[0] or parts[0].startswith("#") or parts[0].lower() == "akips_device":
            continue
        aliases[_short(parts[0])] = parts[1]
    return aliases


class DeviceMatcher:
    """Find the Tenable device for an AKiPS device: alias, then any IP, then sysName, then AKiPS name."""

    def __init__(self, device_index, aliases=None):
        self.by_ip, self.by_name, self.host_os = {}, {}, {}
        for d in device_index.values():
            for ip in d["ips"]:
                self.by_ip.setdefault(ip, d["hostname"])
            for name in d["names"] | {_short(d["hostname"])}:
                self.by_name.setdefault(name, d["hostname"])
            if d.get("os"):
                self.host_os.setdefault(d["hostname"], d["os"])
        self.aliases = aliases or {}

    def match(self, akips_device, ip=None, sys_name=None):
        for key in (_short(akips_device), _short(sys_name)):
            target = self.aliases.get(key) if key else None
            if target:
                return self.by_ip.get(target) or self.by_name.get(_short(target)) or target, "alias"
        if ip and ip in self.by_ip:
            return self.by_ip[ip], "ip"
        if sys_name and _short(sys_name) in self.by_name:
            return self.by_name[_short(sys_name)], "sysName"
        if _short(akips_device) in self.by_name:
            return self.by_name[_short(akips_device)], "name"
        return None, "none"


def build_inventory(akips_rows, tenable_rows, device_index, aliases=None):
    """Join sources into one row per chassis/stack member.

    AKiPS rows win, but blank serial / model / software fields are filled from the matching Tenable
    plugin row (same stack member), so a serial Tenable found is never thrown away."""
    matcher = DeviceMatcher(device_index, aliases)
    tenable_by_host = {}
    for r in tenable_rows:
        tenable_by_host.setdefault(r["hostname"], []).append(r)

    rows = []
    akips_hosts = set()
    for r in akips_rows:
        host, method = matcher.match(r.get("akips_device"), r.get("ip"), r.get("sys_name"))
        if host:
            akips_hosts.add(host)
        row = {
            "hostname": host or r.get("akips_device"),
            "in_tenable": bool(host),
            "akips_device": r.get("akips_device"),
            "ip": r.get("ip"),
            "member": r.get("member"),
            "model": r.get("model") or "",
            "serial": r.get("serial") or "",
            "sw_version": r.get("sw_version") or "",
            "source": "AKiPS",
            "match_method": method,
        }
        if host and not (row["serial"] and row["model"] and row["sw_version"]):
            candidates = tenable_by_host.get(host, [])
            same = [t for t in candidates if t.get("member") == row["member"]] or candidates[:1]
            if same:
                filled = [f for f in ("serial", "model", "sw_version") if not row[f] and same[0].get(f)]
                for field in filled:
                    row[field] = same[0][field]
                if filled:
                    row["source"] = f"AKiPS + Tenable {same[0].get('plugin_id')} ({', '.join(filled)})"
        row["vendor"], row["vendor_source"] = infer_vendor_source(
            [("sysDescr", r.get("sys_descr")), ("entPhysicalDescr", r.get("descr")),
             ("Tenable OS", matcher.host_os.get(host))], model=row["model"])
        rows.append(row)

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
            "match_method": "tenable",
            "vendor_source": f"Tenable plugin {r.get('plugin_id')}",
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


def sample_cisco_keys(cache_dir):
    """(serial, model) of one Cisco chassis in the cached inventory, for API diagnostics."""
    inv = load_inventory(cache_dir)
    if inv.empty:
        return None, None
    cisco_rows = inv[inv["vendor"] == "Cisco"]
    serial = next((s for s in cisco_rows["serial"] if s), None)
    model = next((m for m in cisco_rows["model"] if m), None)
    return serial, model


def has_lifecycle(inv):
    """True when any row has EoX lifecycle data (so lifecycle columns/filters are worth showing)."""
    return inv is not None and not inv.empty and inv["lifecycle"].fillna("").ne("").any()


def cisco_keys(inv):
    """(serials, product IDs) to look up, for Cisco hardware only."""
    cisco_rows = inv[inv["vendor"] == "Cisco"]
    serials = sorted({s for s in cisco_rows["serial"] if s})
    pids = sorted({m for m in cisco_rows["model"] if m})
    return serials, pids


def version_key(version):
    """Comparable key for Cisco release strings: 17.09.04a == 17.9.4a, 15.2(7)E8 == 15.2.7E8."""
    return [(0, int(t)) if t.isdigit() else (1, t.lower()) for t in re.findall(r"\d+|[A-Za-z]+", str(version or ""))]


def software_status(running, suggested):
    """Compare the running release with Cisco's suggested releases for the product."""
    if not suggested:
        return "No suggestion"
    run_key = version_key(running)
    if not run_key:
        return "Suggestion available"
    keys = [version_key(r) for r in suggested]
    if run_key in keys:
        return "On suggested release"
    return "Upgrade suggested" if run_key < max(keys) else "Newer than suggested"


def enrich(inv, cisco_cache, today=None):
    """Add contract, software-suggestion and lifecycle columns from the Cisco cache (no network)."""
    inv = inv.copy()
    for col in CISCO_COLUMNS:
        inv[col] = None
    if inv.empty:
        return inv
    cov_cache, sn_cache, pid_cache = cisco_cache["coverage"], cisco_cache["eox_serial"], cisco_cache["eox_pid"]
    sw_cache = cisco_cache.get("software", {})
    records = []
    for _, row in inv.iterrows():
        serial, model = str(row["serial"]).upper(), str(row["model"]).upper()
        if row["vendor"] != "Cisco":
            records.append({c: None for c in CISCO_COLUMNS} | {"contract": "", "lifecycle": "", "sw_status": ""})
            continue
        cov = (cov_cache.get(serial) if serial else None) or {}
        orderable = str(cov.get("orderable_pid") or "").upper()
        base = str(cov.get("base_pid") or "").upper()

        eox_candidates = [c for c in (sn_cache.get(serial) if serial else None,
                                      pid_cache.get(orderable) if orderable else None,
                                      pid_cache.get(model) if model else None) if c]
        dated = [c for c in eox_candidates if c.get("ldos") or c.get("end_of_sale")]
        eox = dated[0] if dated else next((c for c in eox_candidates if c.get("eox_status")), None)

        sw_keys = [k for k in (model, base, orderable) if k]
        sw_entry = next((sw_cache[k] for k in sw_keys if cisco.has_data(sw_cache.get(k))), None)
        suggested = cisco.suggested_releases(sw_entry)
        looked_up = any(k in sw_cache for k in sw_keys)

        if cov.get("covered") is True:
            contract = "Covered"
        elif cov.get("covered") is False:
            contract = "Not covered"
        else:
            contract = "Unknown" if serial else "No serial"
        records.append({
            "contract": contract,
            "contract_end": cov.get("contract_end"),
            "contract_number": cov.get("contract_number"),
            "service_level": cov.get("service_level"),
            "warranty_end": cov.get("warranty_end"),
            "product_line_end": cov.get("product_line_end"),
            "orderable_pid": cov.get("orderable_pid"),
            "recommended_sw": ", ".join(suggested[:3]) or None,
            "sw_status": software_status(row["sw_version"], suggested) if (suggested or looked_up) else "",
            "lifecycle": lifecycle_status(eox, today) if eox else "",  # blank when EoX isn't in use
            "end_of_sale": (eox or {}).get("end_of_sale"),
            "end_of_sw_maint": (eox or {}).get("end_of_sw_maint"),
            "ldos": (eox or {}).get("ldos"),
            "migration_pid": (eox or {}).get("migration_pid"),
            "bulletin_url": (eox or {}).get("bulletin_url"),
        })
    extra = pd.DataFrame(records, index=inv.index)
    for col in CISCO_COLUMNS:
        inv[col] = extra[col]
    for col in DATE_COLUMNS:
        inv[col] = pd.to_datetime(inv[col], errors="coerce")
    return inv


def device_summary(inv):
    """One row per hostname: models, serial count, worst lifecycle, earliest LDoS, contract status."""
    cols = ["hostname", "model", "members", "serials", "sw_version", "recommended_sw", "sw_status", "lifecycle",
            "ldos", "end_of_sale", "contract", "contract_end", "in_tenable"]
    if inv is None or inv.empty:
        return pd.DataFrame(columns=cols)

    def worst(values, rank=LIFECYCLE_RANK):
        present = [v for v in values if isinstance(v, str)]
        return min(present, key=lambda v: rank.index(v) if v in rank else 99) if present else ""

    def joined(values):
        return ", ".join(dict.fromkeys(v for v in values if isinstance(v, str) and v))

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
        "sw_version": grouped["sw_version"].agg(joined),
        "recommended_sw": grouped["recommended_sw"].agg(joined),
        "sw_status": grouped["sw_status"].agg(lambda v: worst(v, SW_STATUS_RANK)),
        "lifecycle": grouped["lifecycle"].agg(worst),
        "ldos": grouped["ldos"].min(),
        "end_of_sale": grouped["end_of_sale"].min(),
        "contract": grouped["contract"].agg(contract),
        "contract_end": grouped["contract_end"].min(),
        "in_tenable": grouped["in_tenable"].any(),
    }).reset_index()
    return out[cols]


# ---- cache + refresh ---------------------------------------------------------------

def _write(cache_dir, name, rows, **extra):
    Path(cache_dir).mkdir(parents=True, exist_ok=True)
    payload = {"fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "rows": rows, **extra}
    (Path(cache_dir) / name).write_text(json.dumps(payload, default=str))


def _read_payload(cache_dir, name):
    path = Path(cache_dir) / name
    return json.loads(path.read_text()) if path.exists() else {}


def _read(cache_dir, name):
    payload = _read_payload(cache_dir, name)
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


def dump_akips_devices(cache_dir, akips_client, rows, n=2):
    """Full attribute listing for a few devices (preferring ones with a model but no serial)."""
    out = Path(cache_dir) / SAMPLES_DIR
    out.mkdir(parents=True, exist_ok=True)
    no_serial = [r["akips_device"] for r in rows if r["model"] and not r["serial"]]
    devices = list(dict.fromkeys(no_serial + [r["akips_device"] for r in rows]))[:n]
    written = []
    for device in devices:
        path = out / f"akips_device_{re.sub(r'[^A-Za-z0-9_.-]', '_', device)}.txt"
        try:
            path.write_text(akips_client.device_dump(device))
        except Exception as exc:  # noqa: BLE001 - diagnostics only
            path.write_text(f"device dump failed: {exc}")
        written.append(path)
    return written


def refresh(cache_dir, tio=None, akips_client=None, log=None, progress=None, cancelled=None, samples=0):
    """Fetch inventory from whichever sources are given and cache them. Returns a summary dict."""
    log = log or (lambda msg: None)
    summary = {}
    akips_raw = None
    if akips_client is not None:
        log("Fetching hardware inventory from AKiPS ...")
        akips_raw = akips_client.raw_responses(log=log)
        rows, devices = akips.inventory_from_raw(akips_raw)
        _write(cache_dir, AKIPS_FILE, rows, devices=devices)
        summary["akips_chassis"] = len(rows)
        with_serial = sum(1 for r in rows if r["serial"])
        log(f"  AKiPS: {len(rows)} chassis/stack members on {len({r['akips_device'] for r in rows})} devices, "
            f"{sum(1 for r in rows if r['model'])} with model, {with_serial} with serial.")
        if rows and not with_serial:
            log("[yellow]WARNING: AKiPS returned no serial numbers, so contract lookups can't run for "
                "these devices. Run `python -m tenable_net inventory --dump-samples` and check "
                "cache/samples/akips_device_*.txt for where AKiPS keeps the serial.[/yellow]")
        if samples:
            for path in dump_akips_devices(cache_dir, akips_client, rows, samples):
                log(f"  sample written: {path}")
    tenable_records = None
    if tio is not None:
        log(f"Exporting Tenable inventory plugins {sorted(INVENTORY_PLUGINS)} ...")
        tenable_records = export_tenable_inventory(
            tio, progress=progress and (lambda n: progress("inventory", n)), cancelled=cancelled)
        rows = parse_tenable_inventory(tenable_records)
        _write(cache_dir, TENABLE_FILE, rows)
        summary["tenable_chassis"] = len(rows)
        log(f"  Tenable: {len(tenable_records)} plugin results, {len(rows)} chassis parsed, "
            f"{sum(1 for r in rows if r['serial'])} with serial.")
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
    inv = build_inventory(akips_rows, tenable_rows, tenable_device_index(vulns, assets or []), load_aliases())
    return enrich(inv, cisco.load_cache(cache_dir), today)


def refresh_cisco(cache_dir, cisco_client, force=False, log=None):
    inv = load_inventory(cache_dir)
    serials, pids = cisco_keys(inv)
    log = log or (lambda msg: None)
    n_cisco = int((inv["vendor"] == "Cisco").sum()) if not inv.empty else 0
    log(f"Cisco lookups: {n_cisco} of {len(inv)} inventoried chassis are Cisco -> "
        f"{len(serials)} serials, {len(pids)} product IDs.")
    if inv.empty:
        log("[yellow]WARNING: no hardware inventory cached yet; pull inventory first.[/yellow]")
    elif not serials and not pids:
        log("[yellow]WARNING: nothing to look up: no Cisco chassis with a model or serial number.[/yellow]")
    cisco.refresh(cisco_client, serials, pids, cache_dir, force=force, log=log, apis=cisco.enabled_apis())
    return len(serials), len(pids)


def refresh_cisco_device(cache_dir, cisco_client, hostname, log=None):
    """Force a Cisco re-query for one device's serials and models (diagnostics button)."""
    inv = load_inventory(cache_dir)
    rows = inv[(inv["hostname"] == hostname) & (inv["vendor"] == "Cisco")] if not inv.empty else inv
    serials, pids = cisco_keys(rows) if not rows.empty else ([], [])
    log = log or (lambda msg: None)
    log(f"Re-querying Cisco for {hostname}: {len(serials)} serial(s), {len(pids)} product ID(s)")
    cisco.refresh(cisco_client, serials, pids, cache_dir, force=True, log=log, apis=cisco.enabled_apis())
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
