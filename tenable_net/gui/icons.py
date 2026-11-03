"""Line icons drawn for this app (24 x 24 grid, 1.75 px strokes), rendered with QtSvg in any colour.

icon(name, color) gives a QIcon for buttons and lists; paint(painter, name, rect, color) draws one
straight into a delegate; svg_file(name, color) writes a file for stylesheet url(...) rules.
"""

import hashlib
import tempfile
from pathlib import Path

from PySide6.QtCore import QByteArray, QRectF, Qt
from PySide6.QtGui import QIcon, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer

_DOT = "fill='currentColor' stroke='none'"
PATHS = {
    "overview": "<rect x='3.5' y='3.5' width='7' height='9' rx='1.6'/><rect x='13.5' y='3.5' width='7' height='5' "
                "rx='1.6'/><rect x='13.5' y='11.5' width='7' height='9' rx='1.6'/><rect x='3.5' y='15.5' width='7' "
                "height='5' rx='1.6'/>",
    "findings": "<path d='M12 3.2 19 6v5.2c0 4.4-2.9 8.1-7 9.6-4.1-1.5-7-5.2-7-9.6V6z'/><path d='M12 8.3v4.2'/>"
                f"<circle cx='12' cy='15.6' r='1' {_DOT}/>",
    "shield": "<path d='M12 3.2 19 6v5.2c0 4.4-2.9 8.1-7 9.6-4.1-1.5-7-5.2-7-9.6V6z'/>",
    "devices": "<rect x='3.5' y='4' width='17' height='7' rx='2'/><rect x='3.5' y='13' width='17' height='7' rx='2'/>"
               f"<circle cx='7.5' cy='7.5' r='1' {_DOT}/><circle cx='7.5' cy='16.5' r='1' {_DOT}/>",
    "remediation": "<path d='m3.5 6.8 2 2L9 5.3'/><path d='m3.5 15.8 2 2L9 14.3'/><path d='M12.5 7.2h8'/>"
                   "<path d='M12.5 16.2h8'/>",
    "hardware": "<rect x='6' y='6' width='12' height='12' rx='2'/><rect x='9.5' y='9.5' width='5' height='5' rx='.8'/>"
                "<path d='M9.5 3v3M14.5 3v3M9.5 18v3M14.5 18v3M3 9.5h3M3 14.5h3M18 9.5h3M18 14.5h3'/>",
    "trends": "<path d='M3.5 17 9 11.5l3.5 3.5 8-8'/><path d='M15 7h5.5v5.5'/>",
    "diagnostics": "<path d='M3 12h3.5L9 5.5l5 13 2.5-6.5H21'/>",
    "settings": "<path d='M4 7h9M17 7h3M4 17h3M11 17h9'/><circle cx='15' cy='7' r='2'/><circle cx='9' cy='17' r='2'/>",
    "search": "<circle cx='10.5' cy='10.5' r='6'/><path d='m15 15 5 5'/>",
    "export": "<path d='M12 4v10.5'/><path d='m7.5 10 4.5 4.5 4.5-4.5'/>"
              "<path d='M4.5 16.5v2A1.5 1.5 0 0 0 6 20h12a1.5 1.5 0 0 0 1.5-1.5v-2'/>",
    "present": "<rect x='3' y='4' width='18' height='12.5' rx='2'/><path d='M10.3 8.2v4.6l3.9-2.3z' "
               "fill='currentColor'/><path d='M8.5 20.5h7'/>",
    "pull": "<path d='M7 18.5a4.5 4.5 0 0 1-.6-8.96A6 6 0 0 1 18 9.5a4 4 0 0 1 .5 7.97'/><path d='M12 11.5v8'/>"
            "<path d='m8.8 16.5 3.2 3.2 3.2-3.2'/>",
    "reload": "<path d='M4.5 12a7.5 7.5 0 0 1 12.9-5.2L20 9.5'/><path d='M20 4.5v5h-5'/>"
              "<path d='M19.5 12a7.5 7.5 0 0 1-12.9 5.2L4 14.5'/><path d='M4 19.5v-5h5'/>",
    "chevron-down": "<path d='m6.5 9.5 5.5 5.5 5.5-5.5'/>",
    "chevron-up": "<path d='m6.5 14.5 5.5-5.5 5.5 5.5'/>",
    "chevron-right": "<path d='m9.5 6.5 5.5 5.5-5.5 5.5'/>",
    "chevron-left": "<path d='m14.5 6.5-5.5 5.5 5.5 5.5'/>",
    "x": "<path d='m6.5 6.5 11 11M17.5 6.5l-11 11'/>",
    "check": "<path d='m5 12.5 4.5 4.5L19 7.5'/>",
    "filter": "<path d='M4 6.5h16M7 12h10M10 17.5h4'/>",
    "sun": "<circle cx='12' cy='12' r='4'/><path d='M12 2.8v2M12 19.2v2M5.5 5.5l1.4 1.4M17.1 17.1l1.4 1.4M2.8 12h2"
           "M19.2 12h2M5.5 18.5l1.4-1.4M17.1 6.9l1.4-1.4'/>",
    "moon": "<path d='M19.5 14.6A8 8 0 0 1 9.4 4.5a7.6 7.6 0 1 0 10.1 10.1z'/>",
    "monitor": "<rect x='3' y='4' width='18' height='12.5' rx='2'/><path d='M8.5 20.5h7M12 16.5v4'/>",
    "book": "<path d='M5 18.5V6a2.5 2.5 0 0 1 2.5-2.5H19v13H7.5A2.5 2.5 0 0 0 5 19a2.5 2.5 0 0 0 2.5 2.5H19'/>",
    "keyboard": "<rect x='2.5' y='6' width='19' height='12' rx='2'/><path d='M8 14.5h8'/>"
                + "".join(f"<circle cx='{x}' cy='10.2' r='.95' {_DOT}/>" for x in (6.5, 10, 14, 17.5)),
    "info": f"<circle cx='12' cy='12' r='8.5'/><path d='M12 11v5.5'/><circle cx='12' cy='7.9' r='1' {_DOT}/>",
    "help": "<circle cx='12' cy='12' r='8.5'/><path d='M9.7 9.4a2.4 2.4 0 0 1 4.6.9c0 1.6-2.3 2.1-2.3 3.5'/>"
            f"<circle cx='12' cy='16.7' r='1' {_DOT}/>",
    "external": "<path d='M14 4.5h5.5V10'/><path d='M19.5 4.5 11 13'/>"
                "<path d='M17.5 13.5V18a1.5 1.5 0 0 1-1.5 1.5H6A1.5 1.5 0 0 1 4.5 18V8A1.5 1.5 0 0 1 6 6.5h4.5'/>",
    "file": "<path d='M14 3.5H7A1.5 1.5 0 0 0 5.5 5v14A1.5 1.5 0 0 0 7 20.5h10a1.5 1.5 0 0 0 1.5-1.5V8z'/>"
            "<path d='M14 3.5V8h4.5'/><path d='M9 13h6M9 16.5h6'/>",
    "image": "<rect x='3.5' y='4.5' width='17' height='15' rx='2'/><circle cx='9' cy='9.5' r='1.6'/>"
             "<path d='m20.5 15.5-4.5-4.5-9.5 8.5'/>",
    "power": "<path d='M12 3.5v8'/><path d='M7 6.5a7.5 7.5 0 1 0 10 0'/>",
    "arrow-right": "<path d='M5 12h14M13.5 6.5 19 12l-5.5 5.5'/>",
    "alert": "<path d='M10.3 4.6 2.9 17.5a2 2 0 0 0 1.7 3h14.8a2 2 0 0 0 1.7-3L13.7 4.6a2 2 0 0 0-3.4 0z'/>"
             f"<path d='M12 9.5v4'/><circle cx='12' cy='16.9' r='1' {_DOT}/>",
    "hash": "<path d='M5 9h14M5 15h14M10.5 4 8.5 20M15.5 4l-2 16'/>",
    "code": "<path d='m8.5 7.5-4.5 4.5 4.5 4.5M15.5 7.5l4.5 4.5-4.5 4.5'/>",
    "database": "<ellipse cx='12' cy='6' rx='7.5' ry='2.8'/><path d='M4.5 6v12c0 1.5 3.4 2.8 7.5 2.8s7.5-1.3 "
                "7.5-2.8V6'/><path d='M4.5 12c0 1.5 3.4 2.8 7.5 2.8s7.5-1.3 7.5-2.8'/>",
    "zap": "<path d='M13 3 5 13.5h6L10 21l8-10.5h-6z'/>",
    "clock": "<circle cx='12' cy='12' r='8.5'/><path d='M12 7.5V12l3 2'/>",
    "plus": "<path d='M12 5v14M5 12h14'/>",
    "layers": "<path d='m12 3.5 8.5 4.5-8.5 4.5L3.5 8z'/><path d='m3.5 12 8.5 4.5 8.5-4.5'/>"
              "<path d='m3.5 16 8.5 4.5 8.5-4.5'/>",
    "copy": "<rect x='8.5' y='8.5' width='12' height='12' rx='2'/><path d='M15.5 8.5V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 "
            "2v7.5a2 2 0 0 0 2 2h2.5'/>",
}


def svg(name, color):
    """The icon as an SVG document in one colour."""
    body = PATHS[name].replace("currentColor", color)
    return (f"<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' width='24' height='24' fill='none' "
            f"stroke='{color}' stroke-width='1.75' stroke-linecap='round' stroke-linejoin='round'>{body}</svg>")


_renderers, _icons = {}, {}


def renderer(name, color):
    key = (name, color)
    if key not in _renderers:
        _renderers[key] = QSvgRenderer(QByteArray(svg(name, color).encode()))
    return _renderers[key]


def paint(painter, name, rect, color):
    """Draw an icon into rect (QRectF) with an existing painter: vector, so crisp at any scale."""
    renderer(name, color).render(painter, QRectF(rect))


def pixmap(name, color, size=16, ratio=2.0):
    pm = QPixmap(round(size * ratio), round(size * ratio))
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    paint(p, name, QRectF(0, 0, pm.width(), pm.height()), color)
    p.end()
    pm.setDevicePixelRatio(ratio)
    return pm


def icon(name, color, size=16, active_color=None):
    """QIcon in one colour; active_color (optional) is used for the selected / checked state."""
    key = (name, color, size, active_color)
    if key not in _icons:
        ic = QIcon()
        for ratio in (1.0, 2.0):
            ic.addPixmap(pixmap(name, color, size, ratio), QIcon.Normal, QIcon.Off)
            if active_color:
                for mode in (QIcon.Selected, QIcon.Active):
                    ic.addPixmap(pixmap(name, active_color, size, ratio), mode, QIcon.Off)
                ic.addPixmap(pixmap(name, active_color, size, ratio), QIcon.Normal, QIcon.On)
        _icons[key] = ic
    return _icons[key]


ASSET_DIR = Path(tempfile.gettempdir()) / "tenable_net_ui"


def svg_file(name, color):
    """Path (forward slashes, for stylesheet url()) of the icon written as an SVG file. The name carries a
    hash of the content, so a changed icon never picks up a stale file from an older version."""
    text = svg(name, color)
    path = ASSET_DIR / f"{name}-{hashlib.sha1(text.encode()).hexdigest()[:10]}.svg"
    if not path.exists():
        try:
            ASSET_DIR.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        except OSError:  # read-only temp: the stylesheet falls back to Qt's own arrows
            return ""
    return path.as_posix()
