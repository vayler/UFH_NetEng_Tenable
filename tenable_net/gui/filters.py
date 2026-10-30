"""Pure-pandas filtering used by the findings views (kept Qt-free so it is easy to test)."""

import numpy as np
import pandas as pd


TEXT_COLUMNS = ("hostname", "ip", "plugin_name", "cves", "os")
_cache = [None, None]  # [frame, (haystack, plugin ids)] for the frame searched last


def search_index(df):
    """One lowercased string per row over TEXT_COLUMNS, cached so typing doesn't rebuild it per keystroke."""
    if _cache[0] is not df:
        hay = df[TEXT_COLUMNS[0]].fillna("").astype(str)
        for col in TEXT_COLUMNS[1:]:
            hay = hay + "\x1f" + df[col].fillna("").astype(str)  # separator stops terms matching across columns
        _cache[0], _cache[1] = df, (hay.str.lower(), df["plugin_id"].astype(str))
    return _cache[1]


def filter_mask(df, severities=None, states=None, vendor=None, min_vpr=0.0,
                exploitable_only=False, text="", changed_only=False):
    """Return a boolean numpy array selecting rows of the findings frame."""
    mask = pd.Series(True, index=df.index)
    if severities is not None:
        mask &= df["severity"].astype(str).isin(severities)
    if states is not None:
        mask &= df["state"].isin([s.upper() for s in states])
    if vendor:
        mask &= df["vendor"] == vendor
    if min_vpr:
        mask &= df["vpr"].fillna(0) >= min_vpr
    if exploitable_only:
        mask &= df["exploit_available"] == True  # noqa: E712
    if changed_only and "change" in df:
        mask &= df["change"].fillna("") != ""
    terms = text.lower().split()
    if terms:
        hay, ids = search_index(df)
        for term in terms:
            mask &= hay.str.contains(term, regex=False) | (ids == term)
    return mask.to_numpy(dtype=bool) if len(df) else np.zeros(0, dtype=bool)
