"""Pure-pandas filtering used by the findings views (kept Qt-free so it is easy to test)."""

import numpy as np
import pandas as pd


def filter_mask(df, severities=None, states=None, vendor=None, min_vpr=0.0,
                exploitable_only=False, text=""):
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
    for term in text.lower().split():
        term_mask = pd.Series(False, index=df.index)
        for col in ("hostname", "ip", "plugin_name", "cves", "os"):
            term_mask |= df[col].fillna("").astype(str).str.lower().str.contains(term, regex=False)
        term_mask |= df["plugin_id"].astype(str) == term
        mask &= term_mask
    return mask.to_numpy(dtype=bool) if len(df) else np.zeros(0, dtype=bool)
