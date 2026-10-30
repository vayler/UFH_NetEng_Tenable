"""Cisco Support API client.

Three APIs, each optional (CISCO_APIS in .env / Settings picks the ones your API app has):
  sn2info   Serial Number to Information: contract coverage, base/orderable PID by serial
  software  Software Suggestion v2: Cisco-suggested releases by product ID
  eox       EoX: end-of-sale / last-date-of-support by serial or product ID

Hosts and the token URL are overridable via .env (CISCO_API_BASE, CISCO_TOKEN_URL).
Results are cached in cache/cisco.json so repeat runs don't re-query Cisco.
"""

import json
import os
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dotenv import load_dotenv

from tenable_net.client import MissingCredentials, env_path

DEFAULT_TOKEN_URL = "https://id.cisco.com/oauth2/default/v1/token"
DEFAULT_API_BASE = "https://apix.cisco.com"
EOX_SERIAL_PATH = "/supporttools/eox/rest/5/EOXBySerialNumber/{page}/{items}"
EOX_PID_PATH = "/supporttools/eox/rest/5/EOXByProductID/{page}/{items}"
COVERAGE_PATH = "/sn2info/v2/coverage/summary/serial_numbers/{items}"
SOFTWARE_PATH = "/software/suggestion/v2/suggestions/releases/productIds/{items}?pageIndex={page}"
EOX_BATCH = 20
COVERAGE_BATCH = 75
SOFTWARE_BATCH = 10
API_NAMES = {"sn2info": "Serial Number to Info", "software": "Software Suggestion", "eox": "EoX"}
DEFAULT_APIS = ("sn2info", "software")
CACHE_FILE = "cisco.json"
TTL_DAYS = 7


def _date(field):
    """EoX dates are {"value": "2025-01-31", "dateFormat": "YYYY-MM-DD"}; empty value means none."""
    value = field.get("value") if isinstance(field, dict) else field
    return value or None


def _batches(items, size):
    items = list(items)
    for i in range(0, len(items), size):
        yield items[i:i + size]


class CiscoApiError(RuntimeError):
    """A Cisco Support API call failed or returned an error instead of data."""


def _error_message(payload):
    """Return Cisco's error text if the payload is an error response rather than data."""
    if not isinstance(payload, dict):
        return f"unexpected response: {str(payload)[:200]}"
    for key in ("ErrorResponse", "errorResponse", "error", "fault", "Fault"):
        if key in payload:
            return f"{key}: {json.dumps(payload[key])[:300]}"
    return None


def parse_eox(payload):
    """Map each input value (serial or PID) to its lifecycle record."""
    if "EOXRecord" not in payload:
        raise CiscoApiError(f"EoX: {_error_message(payload) or 'response has no EOXRecord'}")
    out = {}
    for rec in payload.get("EOXRecord") or []:
        error = rec.get("EOXError") or {}
        info = {
            "eox_pid": rec.get("EOLProductID") or None,
            "eox_description": rec.get("ProductIDDescription") or None,
            "end_of_sale": _date(rec.get("EndOfSaleDate")),
            "end_of_sw_maint": _date(rec.get("EndOfSWMaintenanceReleases")),
            "ldos": _date(rec.get("LastDateOfSupport")),
            "bulletin_url": rec.get("LinkToProductBulletinURL") or None,
            "migration_pid": (rec.get("EOXMigrationDetails") or {}).get("MigrationProductId") or None,
            "eox_status": "No EoX announced" if error else "Announced",
        }
        for key in str(rec.get("EOXInputValue") or "").split(","):
            if key.strip():
                out[key.strip().upper()] = info
    return out


def parse_coverage(payload):
    if "serial_numbers" not in payload:
        raise CiscoApiError(f"Serial Number to Info: {_error_message(payload) or 'response has no serial_numbers'}")
    out = {}
    for rec in payload.get("serial_numbers") or []:
        serial = str(rec.get("sr_no") or "").strip().upper()
        if not serial:
            continue
        covered = str(rec.get("is_covered") or "").upper()
        pids = rec.get("orderable_pid_list") or []
        bases = rec.get("base_pid_list") or []
        out[serial] = {
            "covered": {"YES": True, "NO": False}.get(covered),
            "contract_end": rec.get("coverage_end_date") or None,
            "contract_number": rec.get("service_contract_number") or None,
            "service_level": rec.get("service_line_descr") or None,
            "warranty_end": rec.get("warranty_end_date") or None,
            "product_line_end": rec.get("covered_product_line_end_date") or None,
            "orderable_pid": (pids[0].get("orderable_pid") if pids and isinstance(pids[0], dict) else None),
            "base_pid": (bases[0].get("base_pid") if bases and isinstance(bases[0], dict) else None),
        }
    return out


NON_OS_SOFTWARE = re.compile(r"rommon|boot|firmware|fpga|bios|capwap|ap software", re.I)


def parse_software(payload, requested=()):
    """Map product ID -> {"product_name", "releases": [{release, date, suggested, software_type}]}.

    Field names follow Cisco's Software Suggestion v2 responses (productList / product / suggestions);
    lookups are defensive because the shape varies by product. Requested PIDs that Cisco reports under
    their base PID (e.g. C9300-48P-E -> C9300-48P) are mapped back by prefix.
    """
    products = payload.get("productList")
    if products is None:
        raise CiscoApiError(f"Software Suggestion: {_error_message(payload) or 'response has no productList'}")
    out = {}
    for item in products or []:
        prod = item.get("product") or {}
        pid = str(prod.get("basePID") or prod.get("basePid") or item.get("productId") or "").strip().upper()
        if not pid and len(requested) == 1:
            pid = requested[0].upper()
        if not pid:
            continue
        entry = out.setdefault(pid, {"product_name": prod.get("productName"), "releases": []})
        for sug in item.get("suggestions") or []:
            if sug.get("errorDetailsResponse"):
                continue
            release = sug.get("releaseFormat1") or sug.get("relDispName") or sug.get("releaseFormat2")
            if not release:
                continue
            entry["releases"].append({
                "release": str(release).strip(),
                "date": sug.get("releaseDate") or None,
                "suggested": str(sug.get("isSuggested", "")).strip().upper() in ("Y", "YES", "TRUE"),
                "software_type": prod.get("softwareType") or sug.get("softwareType") or "",
            })
    for req in requested:  # orderable or longer PIDs reported under a shorter base PID
        key = req.upper()
        if key not in out:
            base = max((p for p in out if key.startswith(p)), key=len, default=None)
            if base:
                out[key] = out[base]
    return out


def suggested_releases(entry):
    """Cisco-suggested OS releases for a product (ROMMON / firmware suggestions left out)."""
    releases = [r for r in (entry or {}).get("releases", []) if not NON_OS_SOFTWARE.search(r.get("software_type") or "")]
    suggested = [r["release"] for r in releases if r.get("suggested")]
    return list(dict.fromkeys(suggested or [r["release"] for r in releases]))


class CiscoClient:
    def __init__(self, client_id, client_secret, token_url=DEFAULT_TOKEN_URL, api_base=DEFAULT_API_BASE,
                 timeout=60, session=None):
        import requests

        self.client_id = client_id
        self.client_secret = client_secret
        self.token_url = token_url
        self.api_base = api_base.rstrip("/")
        self.timeout = timeout
        self.session = session or requests.Session()
        self._token = None
        self._token_expiry = 0

    def token(self):
        if self._token and time.time() < self._token_expiry - 60:
            return self._token
        resp = self.session.post(
            self.token_url,
            data={"grant_type": "client_credentials", "client_id": self.client_id,
                  "client_secret": self.client_secret},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        body = resp.json()
        self._token = body["access_token"]
        self._token_expiry = time.time() + int(body.get("expires_in", 3600))
        return self._token

    def _get(self, path, retries=5):
        delay = 2
        for attempt in range(retries):
            resp = self.session.get(
                self.api_base + path, timeout=self.timeout,
                headers={"Authorization": f"Bearer {self.token()}", "Accept": "application/json"},
            )
            if resp.status_code == 429 or resp.status_code >= 500:
                if attempt == retries - 1:
                    resp.raise_for_status()
                time.sleep(float(resp.headers.get("Retry-After", delay)))
                delay *= 2
                continue
            if resp.status_code == 401 and attempt == 0:
                self._token = None  # expired token: refresh once
                continue
            if resp.status_code >= 400:
                hint = {401: " (credentials rejected for this API)",
                        403: " (this API isn't enabled for your Cisco API app / contract)",
                        404: " (endpoint not found; check CISCO_API_BASE)"}.get(resp.status_code, "")
                raise CiscoApiError(f"HTTP {resp.status_code}{hint} for {path.split('/')[1]}: "
                                    f"{getattr(resp, 'text', '')[:300]}")
            try:
                return resp.json()
            except ValueError as exc:
                raise CiscoApiError(f"non-JSON response for {path}: {getattr(resp, 'text', '')[:200]}") from exc
        raise CiscoApiError(f"gave up on {path} after {retries} attempts (rate limited / server errors)")

    def _eox(self, path_template, values):
        out = {}
        for batch in _batches(values, EOX_BATCH):
            items = ",".join(batch)
            page, last = 1, 1
            while page <= last:
                payload = self._get(path_template.format(page=page, items=items))
                out.update(parse_eox(payload))
                last = int((payload.get("PaginationResponseRecord") or {}).get("LastIndex") or 1)
                page += 1
        return out

    def eox_by_serial(self, serials):
        return self._eox(EOX_SERIAL_PATH, serials)

    def eox_by_pid(self, pids):
        return self._eox(EOX_PID_PATH, pids)

    def coverage(self, serials):
        out = {}
        for batch in _batches(serials, COVERAGE_BATCH):
            out.update(parse_coverage(self._get(COVERAGE_PATH.format(items=",".join(batch)))))
        return out

    def software(self, pids):
        """Suggested releases per product ID. One unknown PID can make Cisco reject a whole batch
        (S3_INV_BASEPID), so a rejected batch is retried one PID at a time."""
        out = {}
        for batch in _batches(pids, SOFTWARE_BATCH):
            try:
                out.update(self._software_batch(batch))
            except CiscoApiError as exc:
                if str(exc).startswith("HTTP 4") or len(batch) == 1:
                    raise
                for pid in batch:
                    try:
                        out.update(self._software_batch([pid]))
                    except CiscoApiError as single:
                        if str(single).startswith("HTTP 4"):
                            raise
        return out

    def _software_batch(self, batch):
        out, page, last = {}, 1, 1
        while page <= last:
            payload = self._get(SOFTWARE_PATH.format(items=",".join(batch), page=page))
            for pid, entry in parse_software(payload, batch).items():
                out.setdefault(pid, {"product_name": entry["product_name"], "releases": []})["releases"] += entry["releases"]
            pages = payload.get("paginationResponseRecord") or {}
            last = int(pages.get("lastIndex") or pages.get("LastIndex") or 1)
            page += 1
        return out


# Probes: a long-retired PID with published EoX dates, and a current PID with suggested releases.
PROBE_PID = "WS-C3750X-48P-S"
PROBE_SOFTWARE_PID = "C9300-48P"


def diagnose(client, serial=None, pid=None):
    """Check the token and every API. Returns [(key, name, ok, detail)], ok None = skipped.

    Never raises for API errors, so it can tell you which APIs your Cisco API app has."""
    try:
        client.token()
    except Exception as exc:  # noqa: BLE001
        return [("token", "Token", False, str(exc)[:200])]
    results = [("token", "Token", True, "issued")]

    if serial:
        try:
            cov = client.coverage([serial]).get(serial.upper())
            detail = (f"{serial}: {'covered until ' + str(cov.get('contract_end')) if cov.get('covered') else 'not covered'}"
                      if cov else f"{serial}: no record (serial not linked to your contracts?)")
            results.append(("sn2info", API_NAMES["sn2info"], True, detail))
        except Exception as exc:  # noqa: BLE001
            results.append(("sn2info", API_NAMES["sn2info"], False, str(exc)[:200]))
    else:
        results.append(("sn2info", API_NAMES["sn2info"], None, "skipped: no serial numbers in the inventory yet"))

    sw_pid = pid or PROBE_SOFTWARE_PID
    try:
        rels = suggested_releases(client.software([sw_pid]).get(sw_pid.upper()))
        results.append(("software", API_NAMES["software"], True,
                        f"{sw_pid}: suggested {', '.join(rels[:3])}" if rels else f"{sw_pid}: no suggestion returned"))
    except Exception as exc:  # noqa: BLE001
        results.append(("software", API_NAMES["software"], False, str(exc)[:200]))

    try:
        rec = client.eox_by_pid([PROBE_PID]).get(PROBE_PID)
        results.append(("eox", API_NAMES["eox"], True,
                        f"{PROBE_PID}: LDoS {rec['ldos']}" if rec and rec.get("ldos") else f"{PROBE_PID}: no record"))
    except Exception as exc:  # noqa: BLE001
        results.append(("eox", API_NAMES["eox"], False, str(exc)[:200]))
    return results


def enabled_apis():
    """APIs to use, from CISCO_APIS (comma-separated keys of API_NAMES)."""
    load_dotenv(env_path())
    raw = os.getenv("CISCO_APIS")
    if raw is None:
        return set(DEFAULT_APIS)
    return {a.strip().lower() for a in raw.split(",") if a.strip().lower() in API_NAMES}


def configured():
    load_dotenv(env_path())
    return bool(os.getenv("CISCO_CLIENT_ID") and os.getenv("CISCO_CLIENT_SECRET"))


def get_client(client_id=None, client_secret=None):
    load_dotenv(env_path())
    client_id = client_id or os.getenv("CISCO_CLIENT_ID")
    client_secret = client_secret or os.getenv("CISCO_CLIENT_SECRET")
    if not client_id or not client_secret:
        raise MissingCredentials("CISCO_CLIENT_ID and CISCO_CLIENT_SECRET must be set (in .env or Settings).")
    return CiscoClient(
        client_id, client_secret,
        token_url=os.getenv("CISCO_TOKEN_URL") or DEFAULT_TOKEN_URL,
        api_base=os.getenv("CISCO_API_BASE") or DEFAULT_API_BASE,
    )


# ---- cache -------------------------------------------------------------------

def load_cache(cache_dir):
    path = Path(cache_dir) / CACHE_FILE
    if not path.exists():
        return {"eox_serial": {}, "eox_pid": {}, "coverage": {}, "software": {}}
    data = json.loads(path.read_text())
    for key in ("eox_serial", "eox_pid", "coverage", "software"):
        data.setdefault(key, {})
    return data


def save_cache(cache_dir, data):
    Path(cache_dir).mkdir(parents=True, exist_ok=True)
    (Path(cache_dir) / CACHE_FILE).write_text(json.dumps(data, indent=1))


MISS_TTL_DAYS = 1


def _stale(entry, now, ttl_days):
    """Hits expire after ttl_days; misses (no data from Cisco) are retried after a day."""
    try:
        fetched = datetime.fromisoformat(entry["fetched_at"])
    except (KeyError, TypeError, ValueError):
        return True
    return now - fetched > timedelta(days=ttl_days if has_data(entry) else MISS_TTL_DAYS)


def has_data(entry):
    """True if a cached result holds anything beyond its timestamp (False counts: "not covered")."""
    return any(v is False or (v not in (None, "") and v != [] and v != {})
               for k, v in (entry or {}).items() if k != "fetched_at")


def refresh(cisco_client, serials, pids, cache_dir, force=False, ttl_days=TTL_DAYS, log=None, apis=None):
    """Query the enabled APIs for serials/PIDs that are missing or stale in the cache, then save it."""
    apis = set(DEFAULT_APIS) if apis is None else set(apis)
    log = log or (lambda msg: None)
    cache = load_cache(cache_dir)
    now = datetime.now(timezone.utc)
    stamp = now.isoformat(timespec="seconds")

    def todo(section, keys):
        keys = sorted({k.strip().upper() for k in keys if k and k.strip()})
        return keys if force else [k for k in keys if k not in cache[section] or _stale(cache[section][k], now, ttl_days)]

    errors = []

    def run(section, keys, fetch, label):
        if not keys:
            log(f"  Cisco {label}: nothing new to look up (cached or none).")
            return
        log(f"  Cisco {label}: querying {len(keys)} ...")
        try:
            results = fetch(keys)
        except CiscoApiError as exc:  # keep going: another API may still be entitled
            log(f"[yellow]WARNING: Cisco {label} failed: {exc}[/yellow]")
            errors.append(f"{label}: {exc}")
            return
        found = sum(1 for k in keys if has_data(results.get(k)))
        log(f"    {found} of {len(keys)} returned data.")
        for key in keys:  # record misses too; they are retried after MISS_TTL_DAYS
            cache[section][key] = {**results.get(key, {}), "fetched_at": stamp}
        save_cache(cache_dir, cache)

    serials = {k.strip().upper() for k in serials if k and k.strip()}
    log(f"  Cisco APIs enabled: {', '.join(API_NAMES[a] for a in API_NAMES if a in apis) or 'none'}")
    if "sn2info" in apis:
        run("coverage", todo("coverage", serials), cisco_client.coverage, "contract coverage (Serial Number to Info)")
    # Coverage also returns the base PID (C9300-48P) and orderable PID (C9300-48P-E) for each serial.
    coverage = [cache["coverage"].get(s) or {} for s in serials]
    base = {c.get("base_pid") for c in coverage} - {None, ""}
    orderable = {c.get("orderable_pid") for c in coverage} - {None, ""}
    if "software" in apis:
        run("software", todo("software", set(pids) | base), cisco_client.software, "software suggestions")
    if "eox" in apis:
        run("eox_serial", todo("eox_serial", serials), cisco_client.eox_by_serial, "EoX by serial")
        run("eox_pid", todo("eox_pid", set(pids) | orderable), cisco_client.eox_by_pid, "EoX by product ID")
    if errors:
        raise CiscoApiError(" | ".join(errors))
    return cache
