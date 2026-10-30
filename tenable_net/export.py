"""Run Tenable bulk exports and cache the raw results locally as JSON.

Bulk exports are much faster than the UI/workbench APIs: Tenable prepares the data
server-side in chunks and pyTenable downloads them, handling polling and rate limits.
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

DEFAULT_CACHE_DIR = Path("cache")
VULNS_FILE = "vulns.json"
ASSETS_FILE = "assets.json"
META_FILE = "meta.json"


PROGRESS_EVERY = 500


def _collect(iterator, progress=None, cancelled=None):
    """Drain an export iterator, reporting progress and honoring cancellation."""
    records = []
    for rec in iterator:
        records.append(rec)
        if len(records) % PROGRESS_EVERY == 0:
            if progress:
                progress(len(records))
            if cancelled and cancelled():
                raise ExportCancelled()
    if progress:
        progress(len(records))
    return records


class ExportCancelled(Exception):
    pass


def export_vulns(tio, severity=None, state=None, since_days=None, include_output=False,
                 progress=None, cancelled=None):
    """Export vulnerability findings. Returns a list of raw finding dicts."""
    kwargs = {"include_plugin_output": include_output}
    if severity:
        kwargs["severity"] = [s.lower() for s in severity]
    if state:
        kwargs["state"] = [s.upper() for s in state]
    if since_days:
        cutoff = datetime.now(timezone.utc) - timedelta(days=since_days)
        kwargs["last_found"] = int(cutoff.timestamp())
    return _collect(tio.exports.vulns(**kwargs), progress, cancelled)


def export_assets(tio, progress=None, cancelled=None):
    """Export the asset inventory. Returns a list of raw asset dicts."""
    return _collect(tio.exports.assets(), progress, cancelled)


def pull(tio, severity, state, since_days=None, include_output=False, skip_assets=False,
         cache_dir=DEFAULT_CACHE_DIR, log=None, progress=None, cancelled=None):
    """Run the vuln (and asset) exports and write them to the cache. Returns the cache meta.

    log(msg) receives status lines; progress(stage, count) receives running record counts.
    """
    log = log or (lambda msg: None)
    filters = {"severity": severity, "state": state, "since_days": since_days}
    log(f"Exporting vulnerabilities {filters} ...")
    vulns = export_vulns(
        tio, severity=severity, state=state, since_days=since_days, include_output=include_output,
        progress=progress and (lambda n: progress("vulns", n)), cancelled=cancelled,
    )
    log(f"  {len(vulns)} findings.")
    assets = []
    if not skip_assets:
        log("Exporting assets ...")
        assets = export_assets(tio, progress=progress and (lambda n: progress("assets", n)), cancelled=cancelled)
        log(f"  {len(assets)} assets.")
    meta = save_cache(vulns, assets, filters, cache_dir)
    try:  # history powers "what changed" and trends; it must never fail a pull
        from tenable_net import history

        history.record(cache_dir)
    except Exception as exc:  # noqa: BLE001
        log(f"  (history snapshot skipped: {exc})")
    return meta


def save_cache(vulns, assets, filters, cache_dir=DEFAULT_CACHE_DIR):
    cache_dir = Path(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    (cache_dir / VULNS_FILE).write_text(json.dumps(vulns, default=str))
    (cache_dir / ASSETS_FILE).write_text(json.dumps(assets, default=str))
    meta = {
        "pulled_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "filters": filters,
        "vuln_count": len(vulns),
        "asset_count": len(assets),
    }
    (cache_dir / META_FILE).write_text(json.dumps(meta, indent=2))
    return meta


def load_cache(cache_dir=DEFAULT_CACHE_DIR):
    """Return (vulns, assets, meta) from the cache. Raises FileNotFoundError if never pulled."""
    cache_dir = Path(cache_dir)
    vulns_path = cache_dir / VULNS_FILE
    if not vulns_path.exists():
        raise FileNotFoundError(f"No cached data in {cache_dir}/. Run `python -m tenable_net pull` first.")
    vulns = json.loads(vulns_path.read_text())
    assets_path = cache_dir / ASSETS_FILE
    assets = json.loads(assets_path.read_text()) if assets_path.exists() else []
    meta_path = cache_dir / META_FILE
    meta = json.loads(meta_path.read_text()) if meta_path.exists() else {}
    return vulns, assets, meta
