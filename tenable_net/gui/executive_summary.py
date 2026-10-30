"""One-page executive summary (PDF) for meetings: risk headline, KPIs with change, top actions, charts."""

import html
from datetime import datetime

from PySide6.QtCore import QMarginsF, QSizeF, QUrl
from PySide6.QtGui import QFont, QPageLayout, QPageSize, QPdfWriter, QTextDocument

from tenable_net.gui import theme

TITLE = "UF Health · Network Vulnerability Summary"


def _delta(change, higher_is_bad=True):
    if change is None:
        return ""
    if change == 0:
        return "<span style='color:#5A6478'>no change</span>"
    worse = (change > 0) == higher_is_bad
    color = "#C62828" if worse else "#2E7D32"
    return f"<span style='color:{color}'>{'▲' if change > 0 else '▼'} {abs(change):,}</span>"


def build_html(data):
    """data keys: fleet (risk.fleet_summary), kpis [(label, value, change, higher_is_bad)], changes (dict|None),
    actions (DataFrame), devices (DataFrame), hardware (dict|None), images {name: (QImage, caption)}."""
    t = theme.TOKENS["light"]  # print in light colours regardless of the app theme
    fleet = data["fleet"]
    now = datetime.now().strftime("%d %B %Y, %H:%M")
    parts = [
        f"<p style='font-size:17pt; font-weight:600; color:{theme.BRAND['navy']}; margin:0'>{TITLE}</p>",
        f"<p style='color:{t['text_muted']}; margin:2px 0 10px 0'>Generated {now} · data pulled "
        f"{html.escape(str(data.get('pulled_at') or 'unknown'))}</p>",
        f"<table width='100%' cellpadding='6' style='background-color:{t['surface_alt']}'><tr>"
        f"<td width='22%'><span style='color:{t['text_muted']}'>FLEET RISK</span><br>"
        f"<span style='font-size:26pt; font-weight:600'>{fleet['index']:.0f}</span><br>"
        f"{theme.band_badge(fleet['band'], fleet['band'] + ' risk').replace(theme.severity_tint(theme.BAND_SEVERITY.get(fleet['band'], 'info')), theme.severity_tint(theme.BAND_SEVERITY.get(fleet['band'], 'info'), 'light'))}"
        f"</td><td>{fleet['devices']:,} devices: "
        + " · ".join(f"<b>{fleet['counts'][b]}</b> {b}" for b in ("Critical", "High", "Elevated", "Low"))
        + (f"<br><br>{data['driver']}" if data.get("driver") else "")
        + "</td></tr></table>",
        "<p style='font-size:12pt; font-weight:600; margin:14px 0 4px 0'>Key numbers</p>",
        "<table width='100%' cellpadding='5'><tr>"
        + "".join(f"<td style='border:1px solid {t['border']}'><span style='color:{t['text_muted']}'>"
                  f"{html.escape(label)}</span><br><span style='font-size:15pt; font-weight:600'>{value}</span>"
                  f"<br>{_delta(change, bad)}</td>" for label, value, change, bad in data["kpis"])
        + "</tr></table>",
    ]
    ch = data.get("changes")
    if ch:
        parts.append(f"<p style='margin:10px 0 0 0'><b>Since the previous pull</b> "
                     f"({html.escape(str(ch['previous_at'])[:16].replace('T', ' '))}): "
                     f"<b>{len(ch['new'])}</b> new, <b>{len(ch['fixed'])}</b> fixed, "
                     f"<b>{len(ch['reopened'])}</b> reopened findings.</p>")
    actions = data.get("actions")
    if actions is not None and not actions.empty:
        rows = "".join(
            f"<tr><td>{r['rank']}</td><td>{html.escape(r['type'])}</td><td>{html.escape(r['title'])}</td>"
            f"<td align='right'>{r['devices']}</td><td align='right'>{r['critical']}</td><td align='right'>{r['high']}</td></tr>"
            for r in actions.head(6).to_dict("records"))
        parts.append("<p style='font-size:12pt; font-weight:600; margin:14px 0 4px 0'>Top actions</p>"
                     f"<table width='100%' cellpadding='4' style='border-collapse:collapse'>"
                     f"<tr style='color:{t['text_muted']}'><td>#</td><td>Type</td><td>Action</td>"
                     f"<td align='right'>Devices</td><td align='right'>Crit</td><td align='right'>High</td></tr>{rows}</table>")
    devices = data.get("devices")
    if devices is not None and not devices.empty:
        rows = "".join(f"<tr><td>{html.escape(str(r['hostname']))}</td><td align='right'>{r['risk']:.0f}</td>"
                       f"<td>{html.escape(str(r['risk_band']))}</td><td>{html.escape(str(r['top_finding']))[:70]}</td></tr>"
                       for r in devices.head(8).to_dict("records"))
        parts.append("<p style='font-size:12pt; font-weight:600; margin:14px 0 4px 0'>Highest-risk devices</p>"
                     f"<table width='100%' cellpadding='3'><tr style='color:{t['text_muted']}'><td>Device</td>"
                     f"<td align='right'>Risk</td><td>Band</td><td>Top finding</td></tr>{rows}</table>")
    hw = data.get("hardware")
    if hw:
        parts.append(f"<p style='margin:10px 0 0 0'><b>Hardware:</b> {hw['chassis']:,} Cisco chassis · "
                     f"{hw['covered']:,} under contract · <b>{hw['uncovered']:,}</b> not covered · "
                     f"{hw['expiring']:,} contracts end within 90 days · {hw['upgrade']:,} on an older release than "
                     "Cisco suggests.</p>")
    images = data.get("images") or {}
    if images:
        parts.append("<table width='100%' cellpadding='4'><tr>"
                     + "".join(f"<td align='center'><span style='color:{t['text_muted']}'>{html.escape(cap)}</span><br>"
                               f"<img src='img://{name}' width='380'></td>" for name, (_img, cap) in images.items())
                     + "</tr></table>")
    return "".join(parts)


def render_pdf(path, data):
    doc = QTextDocument()
    base = QFont("Segoe UI")
    base.setPointSizeF(9.5)
    doc.setDefaultFont(base)
    doc.setDefaultStyleSheet("body { color: #172033; }")
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
