"""One-page executive summary (PDF) for meetings: risk headline, key numbers with change, top actions, charts."""

import html
from datetime import datetime

from PySide6.QtCore import QMarginsF, QSizeF, QUrl
from PySide6.QtGui import QFont, QPageLayout, QPageSize, QPdfWriter, QTextDocument

from tenable_net.gui import theme

TITLE = "UF Health · Network Vulnerability Summary"


def _delta(change, higher_is_bad=True):
    t = theme.TOKENS["light"]
    if change is None:
        return ""
    if change == 0:
        return f"<span style='color:{t['text_muted']}'>no change</span>"
    worse = (change > 0) == higher_is_bad
    color = t["bad"] if worse else t["good"]
    return f"<span style='color:{color}'>{'▲' if change > 0 else '▼'} {abs(change):,}</span>"


def _clip(text, n):
    """One table line: long names are cut with an ellipsis so the summary stays on one page."""
    return text if len(text) <= n else text[:n - 1].rstrip() + "…"


def _heading(text):
    t = theme.TOKENS["light"]
    return (f"<p style='font-size:11.5pt; font-weight:600; color:{t['text']}; margin:16px 0 6px 0'>"
            f"{html.escape(text)}</p>")


def _table(head, rows, t, widths=None):
    widths = widths or [None] * len(head)
    cells = ""
    for (h, a), w in zip(head, widths):
        width = f" width='{w}'" if w else ""
        cells += (f"<td{width} align='{a}' style='color:{t['text_muted']}; border-bottom:1px solid {t['border']}'>"
                  f"{html.escape(h)}</td>")
    body = "".join("<tr>" + "".join(f"<td align='{a}'>{v}</td>" for v, (_h, a) in zip(row, head)) + "</tr>"
                   for row in rows)
    return f"<table width='100%' cellspacing='0' cellpadding='4'><tr>{cells}</tr>{body}</table>"


def build_html(data):
    """data keys: fleet (risk.fleet_summary), kpis [(label, value, change, higher_is_bad)], changes (dict|None),
    actions (DataFrame), devices (DataFrame), hardware (dict|None), images {name: (QImage, caption)}."""
    t = theme.TOKENS["light"]  # print in light colours regardless of the app theme
    fleet = data["fleet"]
    now = datetime.now().strftime("%d %B %Y, %H:%M")
    bands = " &nbsp; ".join(theme.band_badge(b, f"{fleet['counts'][b]} {b.lower()}")
                            for b in ("Critical", "High", "Elevated", "Low"))
    parts = [
        f"<p style='color:{t['accent']}; font-weight:600; margin:0'>UF Health · Network Engineering</p>",
        f"<p style='font-size:18pt; font-weight:600; color:{t['text']}; margin:2px 0 0 0'>"
        "Network vulnerability summary</p>",
        f"<p style='color:{t['text_muted']}; margin:2px 0 14px 0'>Generated {now} · data pulled "
        f"{html.escape(str(data.get('pulled_at') or 'unknown'))}</p>",
        f"<table width='100%' cellpadding='10' cellspacing='0' style='background-color:{t['surface_alt']}'><tr>"
        f"<td width='24%'><span style='color:{t['text_muted']}'>Fleet risk</span><br>"
        f"<span style='font-size:28pt; font-weight:600'>{fleet['index']:.0f}</span><br>"
        f"{theme.band_badge(fleet['band'], fleet['band'] + ' risk')}</td>"
        f"<td><span style='color:{t['text_muted']}'>{fleet['devices']:,} devices by risk band</span><br>{bands}"
        + (f"<br><br>{data['driver']}" if data.get("driver") else "")
        + "</td></tr></table>",
        _heading("Key numbers"),
        "<table width='100%' cellspacing='6' cellpadding='8'><tr>"
        + "".join(f"<td style='border:1px solid {t['border']}'><span style='color:{t['text_muted']}'>"
                  f"{html.escape(label)}</span><br><span style='font-size:16pt; font-weight:600'>{value}</span>"
                  f"<br>{_delta(change, bad)}</td>" for label, value, change, bad in data["kpis"])
        + "</tr></table>",
    ]
    ch = data.get("changes")
    if ch:
        parts.append(f"<p style='margin:10px 0 0 0'><b>Since the previous pull</b> "
                     f"<span style='color:{t['text_muted']}'>"
                     f"({html.escape(str(ch['previous_at'])[:16].replace('T', ' '))})</span>: "
                     f"<b>{len(ch['new'])}</b> new, <b>{len(ch['fixed'])}</b> fixed, "
                     f"<b>{len(ch['reopened'])}</b> reopened findings.</p>")
    actions = data.get("actions")
    if actions is not None and not actions.empty:
        rows = [(r["rank"], html.escape(r["type"]), html.escape(r["title"]), r["devices"], r["critical"], r["high"])
                for r in actions.head(6).to_dict("records")]
        parts.append(_heading("Top actions") + _table(
            [("#", "left"), ("Type", "left"), ("Action", "left"), ("Devices", "right"), ("Crit", "right"),
             ("High", "right")], rows, t, ["4%", "14%", None, "9%", "7%", "7%"]))
    devices = data.get("devices")
    if devices is not None and not devices.empty:
        rows = [(html.escape(str(r["hostname"])), f"{r['risk']:.0f}", theme.band_badge(r["risk_band"]),
                 html.escape(_clip(str(r["top_finding"]), 58))) for r in devices.head(8).to_dict("records")]
        parts.append(_heading("Highest-risk devices") + _table(
            [("Device", "left"), ("Risk", "right"), ("Band", "left"), ("Top finding", "left")], rows, t,
            ["26%", "7%", "12%", None]))
    hw = data.get("hardware")
    if hw:
        parts.append(f"<p style='margin:12px 0 0 0'><b>Hardware:</b> {hw['chassis']:,} Cisco chassis · "
                     f"{hw['covered']:,} under contract · <b>{hw['uncovered']:,}</b> not covered · "
                     f"{hw['expiring']:,} contracts end within 90 days · {hw['upgrade']:,} on an older release than "
                     "Cisco suggests.</p>")
    images = data.get("images") or {}
    if images:
        parts.append("<table width='100%' cellpadding='4' style='margin-top:10px'><tr>"
                     + "".join(f"<td align='center'><span style='color:{t['text_muted']}'>{html.escape(cap)}</span><br>"
                               f"<img src='img://{name}' width='380'></td>" for name, (_img, cap) in images.items())
                     + "</tr></table>")
    return "".join(parts)


def render_pdf(path, data):
    doc = QTextDocument()
    base = QFont()
    base.setFamilies(theme.FAMILIES)
    base.setPointSizeF(9.5)
    doc.setDefaultFont(base)
    doc.setDefaultStyleSheet(f"body {{ color: {theme.TOKENS['light']['text']}; }}")
    for name, (image, _caption) in (data.get("images") or {}).items():
        doc.addResource(QTextDocument.ImageResource, QUrl(f"img://{name}"), image)
    doc.setHtml(build_html(data))
    writer = QPdfWriter(str(path))
    writer.setPageLayout(QPageLayout(QPageSize(QPageSize.A4), QPageLayout.Portrait, QMarginsF(14, 12, 14, 12),
                                     QPageLayout.Millimeter))
    writer.setResolution(110)
    writer.setTitle(TITLE)
    writer.setCreator("tenable_net")
    rect = writer.pageLayout().paintRectPixels(writer.resolution())
    doc.setPageSize(QSizeF(rect.width(), rect.height()))
    doc.print_(writer)
    return path
