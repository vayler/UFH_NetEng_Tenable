"""UF Health design system: colour tokens, severity/status palettes, type scale and the app stylesheet.

Principles: neutral surfaces; UF blue only for the primary action, focus and selection; UF orange only as a
thin accent (active navigation marker); status shown as small coloured dots; severity as soft tinted pills
with dark ink, never large saturated blocks. Brand values live in BRAND; swap the hex codes there if UF
Health's brand guide specifies different ones.
"""

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont, QPalette

BRAND = {
    "blue": "#0021A5",    # UF core blue
    "orange": "#FA4616",  # UF orange: accent marker only
    "navy": "#002657",    # sidebar
}

TOKENS = {
    "light": {
        "bg": "#F4F6F9", "surface": "#FFFFFF", "surface_alt": "#F8FAFC", "border": "#E1E6EE",
        "border_strong": "#C8D0DC", "text": "#172033", "text_muted": "#5A6478", "link": "#0021A5",
        "brand": BRAND["blue"], "brand_hover": "#001A85", "brand_soft": "#E9EEFB", "brand_text": "#FFFFFF",
        "accent": BRAND["orange"],
        "sidebar_bg": BRAND["navy"], "sidebar_text": "#C3CEE4", "sidebar_text_active": "#FFFFFF",
        "sidebar_hover": "#08306A", "sidebar_active": "#0C3A7C", "sidebar_muted": "#8F9EBF",
        "selection": "#E2E9FB", "selection_text": "#0B1F4D",
        "good": "#2E7D32", "warn": "#A65300", "bad": "#C62828", "neutral": "#5F6B7E",
    },
    "dark": {
        "bg": "#0B1220", "surface": "#121A2B", "surface_alt": "#141E31", "border": "#222D44",
        "border_strong": "#33405C", "text": "#E5EAF3", "text_muted": "#9AA4B9", "link": "#9DB2FF",
        "brand": "#3450D8", "brand_hover": "#4462E6", "brand_soft": "#1A2650", "brand_text": "#FFFFFF",
        "accent": "#FF6A3D",
        "sidebar_bg": "#081430", "sidebar_text": "#B8C3DB", "sidebar_text_active": "#FFFFFF",
        "sidebar_hover": "#0F2350", "sidebar_active": "#162D66", "sidebar_muted": "#7F8DAD",
        "selection": "#1E3266", "selection_text": "#FFFFFF",
        "good": "#66BB6A", "warn": "#FFA94D", "bad": "#FF6B6B", "neutral": "#9AA6BD",
    },
}

# Severity hues for charts / dots, plus per-theme "ink" for text on a soft tint of the hue.
SEVERITY_COLORS = {
    "critical": "#C62828",
    "high": "#E07B00",
    "medium": "#E0A800",
    "low": "#00838F",
    "info": "#7B8798",
}
SEVERITY_INK = {
    "light": {"critical": "#9E1B16", "high": "#874500", "medium": "#6E5000", "low": "#00646C", "info": "#4B5668"},
    "dark": {"critical": "#FF9C94", "high": "#FFBA70", "medium": "#F2D06B", "low": "#6BD5DD", "info": "#B3BDCE"},
}
SEVERITY_TINT_ALPHA = {"light": 0.13, "dark": 0.22}
SEVERITY_TEXT = {s: "#FFFFFF" for s in SEVERITY_COLORS}  # text on a solid severity fill (rarely used)

# Status words -> token name, so table cells / badges colour consistently in both themes.
STATUS_TOKENS = {
    "Past LDoS": "bad", "Not covered": "bad", "LDoS < 12 mo": "warn", "End of sale": "warn",
    "Upgrade suggested": "warn", "Covered": "good", "On suggested release": "good", "OK": "good",
}

TYPE_SCALE = {"caption": 0.88, "body": 1.0, "section": 1.08, "title": 1.35, "kpi": 2.0, "brand": 1.25}
BASE_POINT_SIZE = 9.75

_state = {"mode": "light", "presentation": False}


def mode():
    return _state["mode"]


def presentation():
    return _state["presentation"]


def tokens(mode_name=None):
    return TOKENS[mode_name or _state["mode"]]


def color(name, mode_name=None):
    return QColor(tokens(mode_name)[name])


def status_color(value, mode_name=None):
    """Token colour for a status word (Covered, Past LDoS, Upgrade suggested…), or None."""
    token = STATUS_TOKENS.get(str(value))
    return tokens(mode_name)[token] if token else None


def severity_color(severity):
    return QColor(SEVERITY_COLORS.get(str(severity), "#9e9e9e"))


def _blend(fg_hex, bg_hex, alpha):
    fg, bg = QColor(fg_hex), QColor(bg_hex)
    mix = [round(alpha * f + (1 - alpha) * b) for f, b in
           ((fg.red(), bg.red()), (fg.green(), bg.green()), (fg.blue(), bg.blue()))]
    return QColor(*mix).name()


def severity_tint(severity, mode_name=None):
    """Soft background for a severity pill (hex, pre-blended onto the surface colour)."""
    m = mode_name or _state["mode"]
    return _blend(SEVERITY_COLORS.get(severity, "#9e9e9e"), TOKENS[m]["surface"], SEVERITY_TINT_ALPHA[m])


def severity_ink(severity, mode_name=None):
    return SEVERITY_INK[mode_name or _state["mode"]].get(severity, tokens(mode_name)["text"])


BAND_SEVERITY = {"Critical": "critical", "High": "high", "Elevated": "medium", "Low": "low"}


def band_color(band_name):
    """Risk bands reuse the severity hues so colour means the same thing everywhere."""
    return SEVERITY_COLORS[BAND_SEVERITY.get(str(band_name), "info")]


def band_badge(band_name, label=None):
    return severity_badge(BAND_SEVERITY.get(str(band_name), "info"), label if label is not None else str(band_name))


def severity_badge(severity, label=None):
    """Rich-text pill for QLabel / QTextBrowser HTML."""
    sev = str(severity)
    text = label if label is not None else sev.title()
    return (f"<span style='background-color:{severity_tint(sev)}; color:{severity_ink(sev)}; font-weight:600;'>"
            f"&nbsp;{text}&nbsp;</span>")


def font(role="body", bold=False):
    f = QFont()
    scale = TYPE_SCALE.get(role, 1.0) * (1.2 if _state["presentation"] else 1.0)
    f.setPointSizeF(BASE_POINT_SIZE * scale)
    if bold:
        f.setWeight(QFont.DemiBold)
    return f


# ---- contrast (WCAG) ----------------------------------------------------------------

def _luminance(hex_color):
    c = QColor(hex_color)
    channels = []
    for v in (c.redF(), c.greenF(), c.blueF()):
        channels.append(v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4)
    r, g, b = channels
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(fg, bg):
    a, b = sorted((_luminance(fg), _luminance(bg)), reverse=True)
    return (a + 0.05) / (b + 0.05)


def text_pairs(mode_name):
    """(name, foreground, background) pairs that must meet WCAG AA (4.5:1)."""
    t = TOKENS[mode_name]
    pairs = [
        ("text/bg", t["text"], t["bg"]), ("text/surface", t["text"], t["surface"]),
        ("text/surface_alt", t["text"], t["surface_alt"]),
        ("muted/surface", t["text_muted"], t["surface"]), ("muted/bg", t["text_muted"], t["bg"]),
        ("link/surface", t["link"], t["surface"]),
        ("sidebar", t["sidebar_text"], t["sidebar_bg"]), ("sidebar active", t["sidebar_text_active"], t["sidebar_active"]),
        ("sidebar muted", t["sidebar_muted"], t["sidebar_bg"]),
        ("primary button", t["brand_text"], t["brand"]), ("selection", t["selection_text"], t["selection"]),
        ("brand on soft", t["brand"] if mode_name == "light" else t["link"], t["brand_soft"]),
    ]
    pairs += [(f"status {k}/surface", t[k], t["surface"]) for k in ("good", "warn", "bad", "neutral")]
    pairs += [(f"severity {s} pill", severity_ink(s, mode_name), severity_tint(s, mode_name)) for s in SEVERITY_COLORS]
    return pairs


# ---- palette + stylesheet ---------------------------------------------------------------

def palette(mode_name):
    t = TOKENS[mode_name]
    pal = QPalette()
    roles = {
        QPalette.Window: t["bg"], QPalette.WindowText: t["text"], QPalette.Base: t["surface"],
        QPalette.AlternateBase: t["surface_alt"], QPalette.ToolTipBase: t["surface"], QPalette.ToolTipText: t["text"],
        QPalette.Text: t["text"], QPalette.Button: t["surface"], QPalette.ButtonText: t["text"],
        QPalette.BrightText: t["bad"], QPalette.Highlight: t["selection"], QPalette.HighlightedText: t["selection_text"],
        QPalette.Link: t["link"], QPalette.Mid: t["border"], QPalette.PlaceholderText: t["text_muted"],
        QPalette.Light: t["surface"], QPalette.Midlight: t["surface_alt"], QPalette.Dark: t["border_strong"],
    }
    for role, value in roles.items():
        pal.setColor(role, QColor(value))
    for role in (QPalette.Text, QPalette.ButtonText, QPalette.WindowText):
        pal.setColor(QPalette.Disabled, role, QColor(t["text_muted"]))
    return pal


def stylesheet(mode_name):
    t = TOKENS[mode_name]
    return f"""
    QMainWindow, QDialog {{ background: {t['bg']}; }}
    QMenuBar {{ background: {t['surface']}; color: {t['text_muted']}; border-bottom: 1px solid {t['border']}; }}
    QMenuBar::item {{ padding: 4px 10px; background: transparent; }}
    QMenuBar::item:selected {{ background: {t['brand_soft']}; color: {t['text']}; border-radius: 4px; }}
    QMenu {{ background: {t['surface']}; color: {t['text']}; border: 1px solid {t['border']}; padding: 4px; }}
    QMenu::item {{ padding: 5px 22px; border-radius: 4px; }}
    QMenu::item:selected {{ background: {t['brand_soft']}; color: {t['text']}; }}
    QToolTip {{ background: {t['surface']}; color: {t['text']}; border: 1px solid {t['border_strong']}; padding: 6px 8px; }}

    /* sidebar */
    #Sidebar {{ background: {t['sidebar_bg']}; }}
    #Sidebar QLabel {{ color: {t['sidebar_text']}; background: transparent; }}
    #BrandName {{ color: #FFFFFF; }}
    #BrandAccent {{ background: {t['accent']}; }}
    #SidebarCaption, #SidebarVersion {{ color: {t['sidebar_muted']}; }}
    #Nav {{ background: transparent; border: none; outline: 0; }}
    QLabel#SidebarStatus {{ color: {t['sidebar_text']}; padding: 5px 0 5px 26px; border-radius: 6px; margin: 0 8px; }}
    QLabel#SidebarStatus:hover {{ background: {t['sidebar_hover']}; }}
    #Nav::item {{ color: {t['sidebar_text']}; padding-left: 16px; margin: 1px 8px; border-radius: 6px;
        border-left: 3px solid transparent; }}
    #Nav::item:hover {{ background: {t['sidebar_hover']}; }}
    #Nav::item:selected {{ background: {t['sidebar_active']}; color: {t['sidebar_text_active']};
        border-left: 3px solid {t['accent']}; }}

    /* top bar */
    #TopBar {{ background: {t['surface']}; border-bottom: 1px solid {t['border']}; }}
    #PageTitle {{ color: {t['text']}; }}
    QLabel#Muted, #PageSubtitle {{ color: {t['text_muted']}; }}
    QLabel#Chip {{ background: transparent; border: 1px solid {t['border']}; border-radius: 11px; padding: 2px 10px;
        color: {t['text']}; }}
    QLabel#Chip:hover {{ border-color: {t['border_strong']}; background: {t['surface_alt']}; }}

    /* cards and sections */
    QFrame#Card {{ background: {t['surface']}; border: 1px solid {t['border']}; border-radius: 8px; }}
    QFrame#Card:hover {{ border-color: {t['border_strong']}; }}
    QLabel#CardCaption {{ color: {t['text_muted']}; }}
    QLabel#SectionTitle {{ color: {t['text']}; }}
    QGroupBox {{ background: {t['surface']}; border: 1px solid {t['border']}; border-radius: 8px;
        margin-top: 0px; padding: 30px 10px 10px 10px; }}
    QGroupBox::title {{ subcontrol-origin: padding; subcontrol-position: top left; left: 12px; top: 9px;
        color: {t['text']}; font-weight: 600; }}

    /* buttons */
    QPushButton {{ background: {t['surface']}; color: {t['text']}; border: 1px solid {t['border_strong']};
        border-radius: 6px; padding: 5px 14px; min-height: 18px; }}
    QPushButton:hover {{ background: {t['surface_alt']}; border-color: {t['brand']}; }}
    QPushButton:pressed {{ background: {t['brand_soft']}; }}
    QPushButton:disabled {{ color: {t['text_muted']}; background: {t['bg']}; border-color: {t['border']}; }}
    QPushButton#Primary {{ background: {t['brand']}; color: {t['brand_text']}; border: 1px solid {t['brand']}; font-weight: 600; }}
    QPushButton#Primary:hover {{ background: {t['brand_hover']}; border-color: {t['brand_hover']}; }}
    QPushButton#Primary:disabled {{ background: {t['border_strong']}; border-color: {t['border_strong']}; }}

    /* inputs */
    QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox {{ background: {t['surface']}; color: {t['text']};
        border: 1px solid {t['border_strong']}; border-radius: 6px; padding: 4px 8px; min-height: 18px; }}
    QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QDoubleSpinBox:focus {{ border: 1px solid {t['brand']}; }}
    QComboBox::drop-down {{ border: none; width: 20px; }}
    QComboBox QAbstractItemView {{ background: {t['surface']}; border: 1px solid {t['border']};
        selection-background-color: {t['selection']}; selection-color: {t['selection_text']}; }}
    QPlainTextEdit, QTextBrowser {{ background: {t['surface']}; color: {t['text']}; border: 1px solid {t['border']};
        border-radius: 8px; padding: 6px; }}
    QCheckBox {{ spacing: 8px; color: {t['text']}; }}

    /* tables */
    QTableView {{ background: {t['surface']}; alternate-background-color: {t['surface_alt']}; border: 1px solid {t['border']};
        border-radius: 8px; gridline-color: transparent; selection-background-color: {t['selection']};
        selection-color: {t['selection_text']}; }}
    QTableView::item {{ padding: 0 8px; border-bottom: 1px solid {t['border']}; }}
    QTableView::item:selected {{ background: {t['selection']}; color: {t['selection_text']}; }}
    QHeaderView::section {{ background: {t['surface']}; color: {t['text_muted']}; border: none;
        border-bottom: 1px solid {t['border_strong']}; padding: 6px 8px; font-weight: 600; }}
    QTableCornerButton::section {{ background: {t['surface']}; border: none; }}

    QTabWidget::pane {{ border: 1px solid {t['border']}; border-radius: 8px; background: {t['surface']}; top: -1px; }}
    QTabBar::tab {{ padding: 7px 16px; color: {t['text_muted']}; background: transparent; border: none;
        border-bottom: 2px solid transparent; }}
    QTabBar::tab:selected {{ color: {t['text']}; border-bottom: 2px solid {t['brand']}; font-weight: 600; }}
    QTabBar::tab:hover {{ color: {t['text']}; }}
    QSplitter::handle {{ background: transparent; }}
    QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
    QScrollBar::handle:vertical {{ background: {t['border_strong']}; border-radius: 4px; min-height: 30px; }}
    QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
    QScrollBar::handle:horizontal {{ background: {t['border_strong']}; border-radius: 4px; min-width: 30px; }}
    QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
    QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}
    QStatusBar {{ background: {t['surface']}; color: {t['text_muted']}; border-top: 1px solid {t['border']}; }}
    QStatusBar QLabel {{ color: {t['text_muted']}; }}
    QLabel#Toast {{ background: {t['surface']}; color: {t['text']}; border: 1px solid {t['border_strong']};
        border-left: 3px solid {t['brand']}; border-radius: 8px; padding: 10px 16px; }}
    QProgressBar {{ border: 1px solid {t['border']}; border-radius: 4px; background: {t['surface_alt']}; height: 8px; }}
    QProgressBar::chunk {{ background: {t['brand']}; border-radius: 4px; }}
    """


def row_height():
    return 34 if _state["presentation"] else 30


def apply(app, mode_name="system", presentation=None):
    """Apply the theme. mode_name: 'system' | 'light' | 'dark'."""
    app.setStyle("Fusion")
    if presentation is not None:
        _state["presentation"] = bool(presentation)
    hints = app.styleHints()
    if mode_name == "system":
        dark = hasattr(hints, "colorScheme") and hints.colorScheme() == Qt.ColorScheme.Dark
        resolved = "dark" if dark else "light"
    else:
        resolved = mode_name
        if hasattr(hints, "setColorScheme"):
            hints.setColorScheme(Qt.ColorScheme.Dark if resolved == "dark" else Qt.ColorScheme.Light)
    _state["mode"] = resolved
    base = QFont(app.font())
    base.setFamilies(["Segoe UI", "Inter", "Helvetica Neue", "Arial", base.family()])
    base.setPointSizeF(BASE_POINT_SIZE * (1.2 if _state["presentation"] else 1.0))
    app.setFont(base)
    app.setPalette(palette(resolved))
    app.setStyleSheet(stylesheet(resolved))
    return resolved
