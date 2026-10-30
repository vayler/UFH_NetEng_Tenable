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


def export_vulns(tio, severity=None, state=None, since_days=None, include_output=False):
    """Export vulnerability findings. Returns a list of raw finding dicts."""
    kwargs = {"include_plugin_output": include_output}
    if severity:
        kwargs["severity"] = [s.lower() for s in severity]
    if state:
        kwargs["state"] = [s.upper() for s in state]
    if since_days:
        cutoff = datetime.now(timezone.utc) - timedelta(days=since_days)
        kwargs["last_found"] = int(cutoff.timestamp())
    return list(tio.exports.vulns(**kwargs))


def export_assets(tio):
    """Export the asset inventory. Returns a list of raw asset dicts."""
    return list(tio.exports.assets())


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
