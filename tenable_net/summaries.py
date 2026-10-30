"""Terminal summaries rendered with rich."""

import pandas as pd
from rich.console import Console
from rich.table import Table

from tenable_net import reports

SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}

console = Console()


def _fmt(value):
    if value is None or (isinstance(value, float) and pd.isna(value)) or value is pd.NaT:
        return ""
    if isinstance(value, pd.Timestamp):
        return value.strftime("%Y-%m-%d")
    if isinstance(value, float):
        return f"{value:.1f}"
    return str(value)


def print_frame(df, title, columns=None, limit=None):
    """Render a DataFrame as a rich table, coloring severity columns."""
    if df.empty:
        console.print(f"[dim]{title}: no data[/dim]")
        return
    columns = [c for c in (columns or df.columns) if c in df.columns]
    table = Table(title=title, title_justify="left", header_style="bold")
    for col in columns:
        table.add_column(col, style=SEVERITY_STYLE.get(col), overflow="fold",
                         justify="right" if pd.api.types.is_numeric_dtype(df[col]) else "left")
    rows = df.head(limit) if limit else df
    for _, row in rows.iterrows():
        cells = []
        for col in columns:
            text = _fmt(row[col])
            if col == "severity" and text in SEVERITY_STYLE:
                text = f"[{SEVERITY_STYLE[text]}]{text}[/]"
            cells.append(text)
        table.add_row(*cells)
    console.print(table)
    if limit and len(df) > limit:
        console.print(f"[dim]... {len(df) - limit} more rows (use --top to show more, or run `report`)[/dim]")


def summary(findings, meta=None, top=15):
    if meta:
        console.print(f"[dim]Data pulled {meta.get('pulled_at', '?')} | filters: {meta.get('filters', {})}[/dim]")
    console.print(
        f"[bold]{len(findings)}[/bold] findings across "
        f"[bold]{findings['hostname'].nunique()}[/bold] devices\n"
    )
    sev = reports.severity_summary(findings)
    print_frame(sev[(sev["severity"] != "info") | (sev["findings"] > 0)], "Severity")
    print_frame(
        reports.by_device(findings), f"Top {top} devices",
        ["hostname", "ip", "os", "critical", "high", "medium", "low", "total", "max_vpr", "exploitable"], top,
    )
    print_frame(
        reports.by_plugin(findings), f"Top {top} plugins by device count",
        ["plugin_id", "plugin_name", "severity", "devices", "max_vpr", "exploit_available"], top,
    )
    print_frame(
        reports.by_vendor_os(findings), "By vendor / OS",
        ["vendor", "os", "devices", "critical", "high", "medium", "low", "total"], top,
    )


def device(findings, query):
    q = query.lower()
    mask = (
        findings["hostname"].fillna("").str.lower().str.contains(q, regex=False)
        | (findings["ip"].fillna("") == query)
    )
    hits = findings[mask]
    if hits.empty:
        console.print(f"[yellow]No findings for device matching '{query}'[/yellow]")
        return hits
    for (host, ip, os_), group in hits.groupby(["hostname", "ip", "os"], dropna=False):
        print_frame(
            group, f"{host} ({ip}) - {os_}",
            ["severity", "plugin_id", "plugin_name", "vpr", "cves", "port", "last_found"],
        )
    return hits


def search(findings, query):
    """Find devices affected by a CVE, plugin ID, or text in the plugin name."""
    q = query.strip()
    if q.isdigit():
        mask = findings["plugin_id"].astype(str) == q
    elif q.upper().startswith("CVE-"):
        mask = findings["cves"].fillna("").str.upper().str.contains(q.upper(), regex=False)
    else:
        mask = findings["plugin_name"].fillna("").str.lower().str.contains(q.lower(), regex=False)
    hits = findings[mask]
    if hits.empty:
        console.print(f"[yellow]No findings matching '{query}'[/yellow]")
        return hits
    console.print(f"[bold]{hits['hostname'].nunique()}[/bold] devices affected by '{query}'\n")
    print_frame(
        hits, f"Matches for '{query}'",
        ["hostname", "ip", "os", "severity", "plugin_id", "plugin_name", "vpr", "port", "last_found"],
    )
    return hits
