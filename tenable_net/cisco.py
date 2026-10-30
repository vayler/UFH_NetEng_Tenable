"""Cisco Support API client: EoX (lifecycle dates) and SN2INFO (contract coverage).

Endpoints follow Cisco's Support API docs; hosts and the token URL are overridable via .env
(CISCO_API_BASE, CISCO_TOKEN_URL) in case your API registration uses different ones.
Results are cached in cache/cisco.json so repeat runs don't re-query Cisco.
"""

import json
import os
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
EOX_BATCH = 20
COVERAGE_BATCH = 75
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
        out[serial] = {
            "covered": {"YES": True, "NO": False}.get(covered),
            "contract_end": rec.get("coverage_end_date") or None,
            "service_level": rec.get("service_line_descr") or None,
            "warranty_end": rec.get("warranty_end_date") or None,
            "orderable_pid": (pids[0].get("orderable_pid") if pids and isinstance(pids[0], dict) else None),
        }
    return out


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


# A long-retired PID with published EoX dates: a reliable probe that the EoX API answers.
PROBE_PID = "WS-C3750X-48P-S"


def diagnose(client, serial=None, pid=None):
    """Check each API the app uses. Returns [(name, ok, detail)]; never raises for API errors."""
    results = []
    try:
        client.token()
        results.append(("Token", True, "issued"))
    except Exception as exc:  # noqa: BLE001
        return [("Token", False, str(exc)[:200])]
    pids = [PROBE_PID] + ([pid] if pid and pid.upper() != PROBE_PID else [])
    try:
        recs = client.eox_by_pid(pids)
        parts = []
        for p in pids:
            rec = recs.get(p.upper())
            parts.append(f"{p}: LDoS {rec['ldos']}" if rec and rec.get("ldos")
                         else f"{p}: {rec.get('eox_status') if rec else 'no record'}")
        results.append(("EoX", True, "; ".join(parts)))
    except Exception as exc:  # noqa: BLE001
        results.append(("EoX", False, str(exc)[:200]))
    if serial:
        try:
            cov = client.coverage([serial]).get(serial.upper())
            detail = (f"{serial}: {'covered until ' + str(cov.get('contract_end')) if cov.get('covered') else 'not covered'}"
                      if cov else f"{serial}: no record (serial not linked to your contracts?)")
            results.append(("Serial Number to Info", True, detail))
        except Exception as exc:  # noqa: BLE001
            results.append(("Serial Number to Info", False, str(exc)[:200]))
    else:
        results.append(("Serial Number to Info", None, "skipped: no serial numbers in the inventory yet"))
    return results


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
        return {"eox_serial": {}, "eox_pid": {}, "coverage": {}}
    data = json.loads(path.read_text())
    for key in ("eox_serial", "eox_pid", "coverage"):
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
    has_data = any(v not in (None, "") for k, v in entry.items() if k != "fetched_at")
    return now - fetched > timedelta(days=ttl_days if has_data else MISS_TTL_DAYS)


def refresh(cisco_client, serials, pids, cache_dir, force=False, ttl_days=TTL_DAYS, log=None):
    """Query Cisco for serials/PIDs that are missing or stale in the cache, then save it."""
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
        found = sum(1 for k in keys if results.get(k))
        log(f"    {found} of {len(keys)} returned data.")
        for key in keys:  # record misses too; they are retried after MISS_TTL_DAYS
            cache[section][key] = {**results.get(key, {}), "fetched_at": stamp}
        save_cache(cache_dir, cache)

    serials = {k.strip().upper() for k in serials if k and k.strip()}
    run("coverage", todo("coverage", serials), cisco_client.coverage, "contract coverage (Serial Number to Info)")
    # Coverage returns the orderable PID (e.g. C9300-48P-E), which is what EoX knows the product as.
    orderable = {(cache["coverage"].get(s) or {}).get("orderable_pid") for s in serials} - {None, ""}
    run("eox_serial", todo("eox_serial", serials), cisco_client.eox_by_serial, "EoX by serial")
    run("eox_pid", todo("eox_pid", set(pids) | orderable), cisco_client.eox_by_pid, "EoX by product ID")
    if errors:
        raise CiscoApiError(" | ".join(errors))
    return cache
