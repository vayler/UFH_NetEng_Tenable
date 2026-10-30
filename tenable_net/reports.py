"""Rollups and CSV / Excel report writers."""

from datetime import datetime
from pathlib import Path

import pandas as pd

from tenable_net.normalize import SEVERITY_ORDER, vendor_of

REPORT_SEVERITIES = SEVERITY_ORDER


def _severity_counts(df, by):
    counts = (
        df.groupby(by, observed=True)["severity"]
        .value_counts()
        .unstack(fill_value=0)
        .reindex(columns=REPORT_SEVERITIES, fill_value=0)
    )
    if not counts["info"].any():
        counts = counts.drop(columns="info")
    counts["total"] = counts.sum(axis=1)
    return counts


def by_device(df):
    if df.empty:
        return pd.DataFrame()
    counts = _severity_counts(df, ["hostname", "ip", "os"])
    extra = df.groupby(["hostname", "ip", "os"], observed=True).agg(
        max_vpr=("vpr", "max"),
        exploitable=("exploit_available", lambda s: int((s == True).sum())),  # noqa: E712
        last_found=("last_found", "max"),
    )
    out = counts.join(extra).reset_index()
    sort_cols = [c for c in ("critical", "high", "max_vpr") if c in out.columns]
    return out.sort_values(sort_cols, ascending=False).reset_index(drop=True)


def by_plugin(df):
    if df.empty:
        return pd.DataFrame()
    out = (
        df.groupby(["plugin_id", "plugin_name", "severity"], observed=True)
        .agg(
            devices=("hostname", "nunique"),
            max_vpr=("vpr", "max"),
            cvss3=("cvss3", "max"),
            cves=("cves", "first"),
            exploit_available=("exploit_available", "first"),
            solution=("solution", "first"),
        )
        .reset_index()
    )
    return out.sort_values(["severity", "devices", "max_vpr"], ascending=[True, False, False]).reset_index(drop=True)


def by_cve(df):
    if df.empty:
        return pd.DataFrame(columns=["cve", "devices", "severity", "plugins"])
    exploded = df.assign(cve=df["cves"].str.split(", ")).explode("cve")
    exploded = exploded[exploded["cve"].fillna("") != ""]
    if exploded.empty:
        return pd.DataFrame(columns=["cve", "devices", "severity", "plugins"])
    out = (
        exploded.groupby("cve")
        .agg(
            devices=("hostname", "nunique"),
            severity=("severity", "min"),  # ordered categorical: min == most severe
            max_vpr=("vpr", "max"),
            plugins=("plugin_id", lambda s: ", ".join(str(p) for p in sorted(set(s)))),
        )
        .reset_index()
    )
    return out.sort_values(["devices", "max_vpr"], ascending=False).reset_index(drop=True)


def by_vendor_os(df):
    if df.empty:
        return pd.DataFrame()
    df = df.assign(vendor=df["os"].map(vendor_of))
    counts = _severity_counts(df, ["vendor", "os"])
    devices = df.groupby(["vendor", "os"])["hostname"].nunique().rename("devices")
    return counts.join(devices).reset_index().sort_values("total", ascending=False).reset_index(drop=True)


def severity_summary(df):
    counts = df["severity"].value_counts().reindex(REPORT_SEVERITIES, fill_value=0)
    devices = df.groupby("severity", observed=False)["hostname"].nunique().reindex(REPORT_SEVERITIES, fill_value=0)
    return pd.DataFrame({"severity": REPORT_SEVERITIES, "findings": counts.values, "devices": devices.values})


def _excel_safe(df):
    """Excel can't store tz-aware datetimes; also cap cell text at Excel's limit."""
    df = df.copy()
    for col in df.columns:
        if isinstance(df[col].dtype, pd.DatetimeTZDtype):
            df[col] = df[col].dt.tz_localize(None)
        elif df[col].dtype == object:
            df[col] = df[col].map(lambda v: v[:32000] if isinstance(v, str) else v)
        elif isinstance(df[col].dtype, pd.CategoricalDtype):
            df[col] = df[col].astype(str)
    return df


def write_reports(findings, assets=None, out_dir=None, xlsx=True):
    """Write findings.csv and (optionally) a multi-sheet tenable_report.xlsx. Returns written paths."""
    out_dir = Path(out_dir or Path("output") / datetime.now().strftime("%Y-%m-%d_%H%M"))
    out_dir.mkdir(parents=True, exist_ok=True)

    sheets = {
        "Severity Summary": severity_summary(findings),
        "By Device": by_device(findings),
        "By Plugin": by_plugin(findings),
        "By CVE": by_cve(findings),
        "By Vendor-OS": by_vendor_os(findings),
        "Findings": findings.drop(columns=["output"]),
    }
    if assets is not None and not assets.empty:
        sheets["Assets"] = assets

    written = []
    csv_path = out_dir / "findings.csv"
    findings.to_csv(csv_path, index=False)
    written.append(csv_path)
    for name in ("By Device", "By Plugin", "By CVE"):
        path = out_dir / f"{name.lower().replace(' ', '_')}.csv"
        sheets[name].to_csv(path, index=False)
        written.append(path)

    if xlsx:
        xlsx_path = out_dir / "tenable_report.xlsx"
        with pd.ExcelWriter(xlsx_path, engine="openpyxl") as writer:
            for name, frame in sheets.items():
                _excel_safe(frame).to_excel(writer, sheet_name=name, index=False)
                ws = writer.sheets[name]
                ws.freeze_panes = "A2"
                if ws.max_row > 1:
                    ws.auto_filter.ref = ws.dimensions
                for col_cells in ws.columns:
                    width = max((len(str(c.value)) for c in col_cells[:200] if c.value is not None), default=8)
                    ws.column_dimensions[col_cells[0].column_letter].width = min(max(width + 2, 8), 60)
        written.append(xlsx_path)
    return written
