"""Design system: colour tokens, type scale, fonts and the app stylesheet.

The look is quiet and neutral, in the style of modern tools such as Linear: grey surfaces, hairline borders,
compact 13 px type (Inter, bundled), and a single accent colour (UF Health blue) for the primary action, focus,
selection and links. Colour carries meaning only: severity hues in charts and small icons, status as small
dots. Brand values live in BRAND; swap the hex codes there if UF Health's brand guide specifies others.
"""

from pathlib import Path

from PySide6.QtCore import QEvent, QObject, Qt, Signal
from PySide6.QtGui import QColor, QFont, QFontDatabase, QPalette

from tenable_net.gui import icons


class _Signals(QObject):
    changed = Signal(str)  # emitted by apply() with the resolved mode; widgets with baked-in colours re-tint


signals = _Signals()

BRAND = {
    "blue": "#0021A5",    # UF core blue: the accent
    "orange": "#FA4616",  # UF orange: workspace tile only
    "navy": "#002657",
}

TOKENS = {
    "light": {
        "bg": "#F4F4F6", "surface": "#FFFFFF", "surface_alt": "#F8F8FA", "raised": "#FFFFFF", "raised_hover": "#EDEDF0",
        "hover": "#EBEBEE", "row_hover": "#F6F6F8", "active": "#E7E7EB",
        "border": "#E8E8EC", "border_strong": "#D7D7DD", "divider": "#EFEFF2",
        "text": "#18181B", "text_muted": "#61616B", "text_faint": "#8E8E98",
        "accent": BRAND["blue"], "accent_hover": "#001B8A", "accent_soft": "#E8ECFB", "accent_border": "#C5CFF3",
        "accent_text": "#1D3BC4", "on_accent": "#FFFFFF", "focus": "#3A57D6",
        "selection": "#E8ECFB", "selection_text": "#18181B",
        "good": "#18794E", "warn": "#A35200", "bad": "#CA2A30", "neutral": "#6F6F78",
        "dot_good": "#30A46C", "dot_warn": "#F5A524", "dot_bad": "#E5484D", "dot_neutral": "#A1A1AA",
        "scroll": "#D4D4DA", "scroll_hover": "#A9A9B2",
        "tooltip_bg": "#1F1F23", "tooltip_text": "#F4F4F5", "tooltip_border": "#1F1F23",
        "kbd_bg": "#F1F1F4", "kbd_border": "#E1E1E6", "kbd_text": "#61616B",
        "scrim": "rgba(24, 24, 27, 56)",  # stylesheet alpha is 0-255
    },
    "dark": {
        "bg": "#0E0E10", "surface": "#151517", "surface_alt": "#1B1B1E", "raised": "#1C1C1F", "raised_hover": "#2C2C31",
        "hover": "#1D1D20", "row_hover": "#1A1A1D", "active": "#232327",
        "border": "#252529", "border_strong": "#303035", "divider": "#202024",
        "text": "#ECECEF", "text_muted": "#A1A1AA", "text_faint": "#6E6E78",
        "accent": "#3D5AFE", "accent_hover": "#4A63FF", "accent_soft": "#1F2550", "accent_border": "#34408A",
        "accent_text": "#9CACFF", "on_accent": "#FFFFFF", "focus": "#6C82FF",
        "selection": "#1F2550", "selection_text": "#ECECEF",
        "good": "#4CC38A", "warn": "#F1A33C", "bad": "#FF6B70", "neutral": "#9A9AA5",
        "dot_good": "#3DD68C", "dot_warn": "#F5A524", "dot_bad": "#FF6369", "dot_neutral": "#71717A",
        "scroll": "#34343A", "scroll_hover": "#4A4A52",
        "tooltip_bg": "#2A2A2F", "tooltip_text": "#ECECEF", "tooltip_border": "#36363C",
        "kbd_bg": "#232327", "kbd_border": "#303035", "kbd_text": "#A1A1AA",
        "scrim": "rgba(0, 0, 0, 120)",
    },
}
for _t in TOKENS.values():  # names older code uses
    _t.update(brand=_t["accent"], brand_hover=_t["accent_hover"], brand_soft=_t["accent_soft"],
              brand_text=_t["on_accent"], link=_t["accent_text"])

# Severity hues: chart fills, severity icons, dots. Text stays in the normal text colour beside them.
SEVERITY_COLORS = {
    "critical": "#E5484D",
    "high": "#F76B15",
    "medium": "#F0B90B",
    "low": "#12A594",
    "info": "#8B8D98",
}
SEVERITY_TEXT = {s: "#FFFFFF" for s in SEVERITY_COLORS}  # text on a solid severity fill (rarely used)

# Status words -> token name, so table cells / badges colour consistently in both themes.
STATUS_TOKENS = {
    "Past LDoS": "bad", "Not covered": "bad", "LDoS < 12 mo": "warn", "End of sale": "warn",
    "Upgrade suggested": "warn", "Covered": "good", "On suggested release": "good", "OK": "good",
    "Newer than suggested": "good", "Current": "good", "Unknown": "neutral", "No serial": "neutral",
    "No suggestion": "neutral", "Not Cisco": "neutral", "Not looked up yet": "warn",
    "New": "warn", "Reopened": "bad",
    "Confirmed": "good", "Likely": "warn", "Check": "warn", "Find release": "neutral",
}

# Pixel sizes. 13 px body text is the Linear-style default; presentation mode scales everything.
TYPE_SCALE = {"caption": 12, "small": 12, "body": 13, "label": 13, "section": 14, "title": 15, "headline": 20,
              "kpi": 26, "display": 40, "brand": 14, "mono": 12}
ROLE_WEIGHT = {"section": "semibold", "title": "semibold", "headline": "semibold", "kpi": "medium",
               "display": "semibold", "brand": "semibold"}
PRESENTATION_SCALE = 1.22
BASE_PIXEL_SIZE = TYPE_SCALE["body"]
FAMILIES = ["Inter", "Segoe UI Variable Text", "Segoe UI", "SF Pro Text", "Helvetica Neue", "Arial"]
MONO_FAMILIES = ["JetBrains Mono", "Cascadia Mono", "Consolas", "SF Mono", "Menlo", "DejaVu Sans Mono", "monospace"]
FONT_DIR = Path(__file__).parent / "fonts"

_state = {"mode": "light", "presentation": False, "fonts": None}


def mode():
    return _state["mode"]


def presentation():
    return _state["presentation"]


def tokens(mode_name=None):
    return TOKENS[mode_name or _state["mode"]]


def color(name, mode_name=None):
    return QColor(tokens(mode_name)[name])


def status_token(value):
    return STATUS_TOKENS.get(str(value))


def status_color(value, mode_name=None):
    """Text colour for a status word (Covered, Past LDoS, Upgrade suggested…), or None."""
    token = status_token(value)
    return tokens(mode_name)[token] if token else None


def status_dot(value, mode_name=None):
    """Brighter dot colour for a status word, or None."""
    token = status_token(value)
    return tokens(mode_name)[f"dot_{token}"] if token else None


def severity_color(severity):
    return QColor(SEVERITY_COLORS.get(str(severity), "#9e9e9e"))


def _blend(fg_hex, bg_hex, alpha):
    fg, bg = QColor(fg_hex), QColor(bg_hex)
    mix = [round(alpha * f + (1 - alpha) * b) for f, b in
           ((fg.red(), bg.red()), (fg.green(), bg.green()), (fg.blue(), bg.blue()))]
    return QColor(*mix).name()


def blend(fg_hex, bg_hex, alpha):
    """fg over bg at alpha, as a hex colour."""
    return _blend(fg_hex, bg_hex, alpha)


BAND_SEVERITY = {"Critical": "critical", "High": "high", "Elevated": "medium", "Low": "low"}


def band_color(band_name):
    """Risk bands reuse the severity hues so colour means the same thing everywhere."""
    return SEVERITY_COLORS[BAND_SEVERITY.get(str(band_name), "info")]


def dot_badge(hex_color, label, weight=500):
    """Rich-text label with a coloured dot (for QLabel / QTextBrowser HTML)."""
    return (f"<span style='color:{hex_color}'>●</span>&nbsp;"
            f"<span style='font-weight:{weight}'>{label}</span>")


def severity_badge(severity, label=None):
    sev = str(severity)
    return dot_badge(SEVERITY_COLORS.get(sev, SEVERITY_COLORS["info"]), label if label is not None else sev.title())


def band_badge(band_name, label=None):
    return severity_badge(BAND_SEVERITY.get(str(band_name), "info"), label if label is not None else str(band_name))


def status_badge(value, label=None):
    """Dot + text for a status word; plain text when the word has no status colour."""
    dot = status_dot(value)
    text = label if label is not None else str(value)
    return dot_badge(dot, text) if dot else text


# ---- fonts ------------------------------------------------------------------------------

def load_fonts():
    """Register the bundled Inter faces once. Returns the families Qt reports for them."""
    if _state["fonts"] is None:
        families = set()
        for path in sorted(FONT_DIR.glob("*.otf")):
            font_id = QFontDatabase.addApplicationFont(str(path))
            if font_id >= 0:
                families.update(QFontDatabase.applicationFontFamilies(font_id))
        _state["fonts"] = families
    return _state["fonts"]


def _weight(name):
    return {"regular": QFont.Normal, "medium": QFont.Medium, "semibold": QFont.DemiBold}[name]


def _families(weight_name):
    """Font families for a weight. Older Windows font databases list each static Inter weight as its own
    family ("Inter Medium"); prefer that family so Qt doesn't fake the weight."""
    loaded = _state["fonts"] or set()
    legacy = {"medium": "Inter Medium", "semibold": "Inter SemiBold"}.get(weight_name)
    return ([legacy] if legacy in loaded else []) + FAMILIES


def _tabular(f):
    try:
        f.setFeature(QFont.Tag("tnum"), 1)
    except (AttributeError, TypeError, ValueError):  # Qt < 6.7: proportional figures, still fine
        pass
    return f


def font(role="body", bold=False, weight=None, tabular=None):
    """A type-scale font. weight: regular | medium | semibold (bold=True means semibold)."""
    weight = weight or ("semibold" if bold else ROLE_WEIGHT.get(role, "regular"))
    f = QFont()
    f.setFamilies(_families(weight))
    px = TYPE_SCALE.get(role, BASE_PIXEL_SIZE) * (PRESENTATION_SCALE if _state["presentation"] else 1.0)
    f.setPixelSize(max(round(px), 8))
    f.setWeight(_weight(weight))
    if px >= 18:  # display sizes read better slightly tighter
        f.setLetterSpacing(QFont.PercentageSpacing, 98.0)
    if tabular or (tabular is None and role in ("kpi", "display")):
        _tabular(f)
    return f


def mono_font(role="mono"):
    f = QFont()
    f.setFamilies(MONO_FAMILIES)
    f.setStyleHint(QFont.Monospace)
    f.setPixelSize(round(TYPE_SCALE.get(role, 12) * (PRESENTATION_SCALE if _state["presentation"] else 1.0)))
    return f


def set_font(widget, role="body", bold=False, weight=None):
    """Set a type-scale font and remember the role, so refresh_fonts() can rescale it later."""
    widget.setProperty("font_role", role)
    widget.setProperty("font_bold", bool(bold))
    widget.setProperty("font_weight", weight or "")
    widget.setFont(font(role, bold, weight or None))


def table_font():
    return _tabular(font("body"))


def refresh_fonts(root):
    """Re-apply type-scale fonts and table row heights (after presentation mode toggles)."""
    from PySide6.QtWidgets import QTableView, QWidget

    for widget in [root, *root.findChildren(QWidget)]:
        role = widget.property("font_role")
        if role:
            widget.setFont(font(role, bool(widget.property("font_bold")), widget.property("font_weight") or None))
    for table in root.findChildren(QTableView):
        table.setFont(table_font())
        table.verticalHeader().setDefaultSectionSize(row_height())


def row_height():
    return 38 if _state["presentation"] else 32


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
    pairs = [(f"text/{bg}", t["text"], t[bg]) for bg in ("bg", "surface", "surface_alt", "raised", "raised_hover",
                                                          "hover", "row_hover", "active", "selection")]
    pairs += [(f"muted/{bg}", t["text_muted"], t[bg]) for bg in ("bg", "surface", "surface_alt", "raised", "hover",
                                                                  "active")]
    pairs += [
        ("link/surface", t["accent_text"], t["surface"]), ("link/raised", t["accent_text"], t["raised"]),
        ("primary button", t["on_accent"], t["accent"]), ("primary hover", t["on_accent"], t["accent_hover"]),
        ("active chip", t["accent_text"], t["accent_soft"]), ("tooltip", t["tooltip_text"], t["tooltip_bg"]),
        ("kbd", t["kbd_text"], t["kbd_bg"]),
    ]
    pairs += [(f"status {k}/{bg}", t[k], t[bg]) for k in ("good", "warn", "bad", "neutral")
              for bg in ("surface", "surface_alt")]
    return pairs


# ---- palette + stylesheet ---------------------------------------------------------------

def palette(mode_name):
    t = TOKENS[mode_name]
    pal = QPalette()
    roles = {
        QPalette.Window: t["bg"], QPalette.WindowText: t["text"], QPalette.Base: t["surface"],
        QPalette.AlternateBase: t["surface_alt"], QPalette.ToolTipBase: t["tooltip_bg"],
        QPalette.ToolTipText: t["tooltip_text"], QPalette.Text: t["text"], QPalette.Button: t["surface"],
        QPalette.ButtonText: t["text"], QPalette.BrightText: t["bad"], QPalette.Highlight: t["selection"],
        QPalette.HighlightedText: t["selection_text"], QPalette.Link: t["accent_text"],
        QPalette.LinkVisited: t["accent_text"], QPalette.Mid: t["border"], QPalette.PlaceholderText: t["text_faint"],
        QPalette.Light: t["surface"], QPalette.Midlight: t["surface_alt"], QPalette.Dark: t["border_strong"],
        QPalette.Shadow: t["border_strong"],
    }
    for role, value in roles.items():
        pal.setColor(role, QColor(value))
    for role in (QPalette.Text, QPalette.ButtonText, QPalette.WindowText):
        pal.setColor(QPalette.Disabled, role, QColor(t["text_faint"]))
    return pal


def _url(path):
    return f"url({path})" if path else "none"


def stylesheet(mode_name):
    t = TOKENS[mode_name]
    chevron = _url(icons.svg_file("chevron-down", t["text_muted"]))
    chevron_up = _url(icons.svg_file("chevron-up", t["text_muted"]))
    chevron_right = _url(icons.svg_file("chevron-right", t["text_muted"]))
    sort_down = _url(icons.svg_file("chevron-down", t["text_faint"]))
    sort_up = _url(icons.svg_file("chevron-up", t["text_faint"]))
    check = _url(icons.svg_file("check", t["on_accent"]))
    check_menu = _url(icons.svg_file("check", t["text"]))
    return f"""
    QMainWindow, #AppRoot {{ background: {t['bg']}; }}
    QDialog {{ background: {t['surface']}; }}
    QWidget {{ outline: 0; }}
    QToolTip {{ background: {t['tooltip_bg']}; color: {t['tooltip_text']}; border: 1px solid {t['tooltip_border']};
        border-radius: 6px; padding: 5px 8px; }}

    /* menus */
    QMenu {{ background: {t['raised']}; color: {t['text']}; border: 1px solid {t['border_strong']};
        border-radius: 8px; padding: 4px; }}
    QMenu::item {{ padding: 6px 28px 6px 10px; border-radius: 5px; background: transparent; }}
    QMenu::item:selected {{ background: {t['raised_hover']}; color: {t['text']}; }}
    QMenu::item:disabled {{ color: {t['text_faint']}; }}
    QMenu::icon {{ padding-left: 8px; }}
    QMenu::separator {{ height: 1px; background: {t['border']}; margin: 4px 6px; }}
    QMenu::right-arrow {{ image: {chevron_right}; width: 12px; height: 12px; right: 8px; }}
    QMenu::indicator {{ width: 14px; height: 14px; left: 6px; }}
    QMenu::indicator:checked {{ image: {check_menu}; }}

    /* sidebar */
    #Sidebar {{ background: transparent; }}
    QLabel#SidebarCaption {{ color: {t['text_muted']}; padding: 0 0 0 10px; }}
    QLabel#SidebarVersion {{ color: {t['text_faint']}; }}
    QListWidget#NavList {{ background: transparent; border: none; }}

    /* content panel + page header */
    QFrame#ContentPanel {{ background: {t['surface']}; border: 1px solid {t['border']}; border-radius: 10px; }}
    QFrame#PageHeader {{ background: transparent; border: none; border-bottom: 1px solid {t['border']};
        border-top-left-radius: 10px; border-top-right-radius: 10px; }}
    QLabel#PageTitle {{ color: {t['text']}; }}
    QLabel#PageSubtitle, QLabel#Muted {{ color: {t['text_muted']}; }}
    QLabel#Faint {{ color: {t['text_faint']}; }}
    QFrame#Toolbar {{ background: transparent; border: none; }}
    QFrame#Divider {{ background: {t['border']}; border: none; }}

    /* panels (sections), stat tiles */
    QFrame#Panel, QFrame#Card {{ background: {t['surface']}; border: 1px solid {t['border']}; border-radius: 10px; }}
    QFrame#Panel QLabel, QFrame#Card QLabel {{ background: transparent; border: none; }}
    QLabel#PanelTitle {{ color: {t['text']}; }}
    QFrame#StatTile {{ background: transparent; border: none; border-radius: 8px; }}
    QFrame#StatTile:hover {{ background: {t['row_hover']}; }}
    QFrame#StatTile QLabel {{ background: transparent; }}
    QLabel#StatCaption {{ color: {t['text_muted']}; }}
    QFrame#EmptyCard {{ background: {t['surface']}; border: 1px solid {t['border']}; border-radius: 12px; }}

    /* buttons */
    QPushButton {{ background: {t['surface']}; color: {t['text']}; border: 1px solid {t['border_strong']};
        border-radius: 6px; padding: 0 12px; min-height: 28px; }}
    QPushButton:hover {{ background: {t['surface_alt']}; border-color: {t['text_faint']}; }}
    QPushButton:pressed {{ background: {t['hover']}; }}
    QPushButton:focus {{ border-color: {t['focus']}; }}
    QPushButton:disabled {{ color: {t['text_faint']}; background: {t['surface']}; border-color: {t['border']}; }}
    QPushButton::menu-indicator {{ image: none; width: 0; }}
    QPushButton#Primary, QPushButton[variant="primary"] {{ background: {t['accent']}; color: {t['on_accent']};
        border: 1px solid {t['accent']}; }}
    QPushButton#Primary:hover, QPushButton[variant="primary"]:hover {{ background: {t['accent_hover']};
        border-color: {t['accent_hover']}; }}
    QPushButton#Primary:disabled, QPushButton[variant="primary"]:disabled {{ background: {t['border_strong']};
        border-color: {t['border_strong']}; color: {t['surface']}; }}
    QPushButton[variant="ghost"] {{ background: transparent; border: 1px solid transparent; color: {t['text_muted']};
        padding: 0 8px; }}
    QPushButton[variant="ghost"]:hover {{ background: {t['hover']}; color: {t['text']}; }}
    QPushButton[variant="ghost"]:checked {{ background: {t['active']}; color: {t['text']}; }}
    QPushButton[variant="ghost"]:disabled {{ background: transparent; color: {t['text_faint']}; }}
    QPushButton[variant="link"] {{ background: transparent; border: none; color: {t['accent_text']}; padding: 0 4px;
        min-height: 22px; }}
    QPushButton[variant="link"]:hover {{ text-decoration: underline; background: transparent; }}
    QPushButton[chip="true"] {{ background: transparent; color: {t['text_muted']}; border: 1px solid
        {t['border']}; padding: 0 10px; min-height: 26px; }}
    QPushButton[chip="true"]:hover {{ color: {t['text']}; background: {t['surface_alt']}; }}
    QPushButton[chip="true"][active="true"], QPushButton[chip="true"]:checked {{ background: {t['accent_soft']};
        color: {t['accent_text']}; border: 1px solid {t['accent_border']}; }}
    QPushButton[segment="true"] {{ background: transparent; border: 1px solid transparent; color: {t['text_muted']};
        border-radius: 5px; padding: 0 10px; min-height: 24px; }}
    QPushButton[segment="true"]:hover {{ color: {t['text']}; }}
    QPushButton[segment="true"]:checked {{ background: {t['surface']}; color: {t['text']};
        border: 1px solid {t['border_strong']}; }}
    QFrame#Segmented {{ background: {t['surface_alt']}; border: 1px solid {t['border']}; border-radius: 7px; }}
    QToolButton {{ background: transparent; border: 1px solid transparent; border-radius: 6px; padding: 3px; }}
    QToolButton:hover {{ background: {t['hover']}; }}
    QToolButton:checked {{ background: {t['active']}; }}
    QToolButton::menu-indicator {{ image: none; width: 0; }}

    /* inputs */
    QLineEdit, QAbstractSpinBox {{ background: {t['surface']}; color: {t['text']};
        border: 1px solid {t['border_strong']}; border-radius: 6px; padding: 0 8px; min-height: 28px;
        selection-background-color: {t['accent_soft']}; selection-color: {t['text']}; }}
    QLineEdit:hover, QAbstractSpinBox:hover {{ border-color: {t['text_faint']}; }}
    QLineEdit:focus, QAbstractSpinBox:focus {{ border-color: {t['focus']}; }}
    QLineEdit:disabled, QAbstractSpinBox:disabled {{ color: {t['text_faint']}; background: {t['surface_alt']}; }}
    QAbstractSpinBox {{ padding-right: 20px; }}
    QAbstractSpinBox::up-button {{ subcontrol-origin: border; subcontrol-position: top right; width: 18px;
        border: none; margin: 3px 3px 0 0; }}
    QAbstractSpinBox::down-button {{ subcontrol-origin: border; subcontrol-position: bottom right; width: 18px;
        border: none; margin: 0 3px 3px 0; }}
    QAbstractSpinBox::up-arrow {{ image: {chevron_up}; width: 10px; height: 10px; }}
    QAbstractSpinBox::down-arrow {{ image: {chevron}; width: 10px; height: 10px; }}
    QComboBox {{ background: {t['surface']}; color: {t['text']}; border: 1px solid {t['border_strong']};
        border-radius: 6px; padding: 0 28px 0 10px; min-height: 28px; combobox-popup: 0; }}
    QComboBox:hover {{ border-color: {t['text_faint']}; background: {t['surface_alt']}; }}
    QComboBox:focus {{ border-color: {t['focus']}; }}
    QComboBox[active="true"] {{ background: {t['accent_soft']}; color: {t['accent_text']};
        border-color: {t['accent_border']}; }}
    QComboBox::drop-down {{ subcontrol-origin: padding; subcontrol-position: center right; width: 24px;
        border: none; }}
    QComboBox::down-arrow {{ image: {chevron}; width: 12px; height: 12px; }}
    QComboBox QAbstractItemView {{ background: {t['raised']}; color: {t['text']};
        border: 1px solid {t['border_strong']}; padding: 4px; outline: 0;
        selection-background-color: {t['raised_hover']}; selection-color: {t['text']}; }}
    QComboBox QAbstractItemView::item {{ min-height: 28px; padding: 0 8px; border-radius: 5px; }}
    QComboBox QAbstractItemView::item:selected, QComboBox QAbstractItemView::item:hover {{
        background: {t['raised_hover']}; color: {t['text']}; }}
    QCheckBox, QRadioButton {{ spacing: 8px; color: {t['text']}; background: transparent; }}
    QCheckBox:disabled, QRadioButton:disabled {{ color: {t['text_faint']}; }}
    QCheckBox::indicator {{ width: 14px; height: 14px; border: 1px solid {t['border_strong']}; border-radius: 4px;
        background: {t['surface']}; }}
    QCheckBox::indicator:hover {{ border-color: {t['text_faint']}; }}
    QCheckBox::indicator:checked {{ background: {t['accent']}; border-color: {t['accent']}; image: {check}; }}
    QCheckBox::indicator:disabled {{ background: {t['surface_alt']}; border-color: {t['border']}; }}
    QCheckBox::indicator:checked:disabled {{ background: {t['border_strong']}; border-color: {t['border_strong']}; }}
    QRadioButton::indicator {{ width: 14px; height: 14px; border: 1px solid {t['border_strong']}; border-radius: 8px;
        background: {t['surface']}; }}
    QRadioButton::indicator:checked {{ border: 4px solid {t['accent']}; width: 8px; height: 8px; }}
    QPlainTextEdit, QTextEdit {{ background: {t['surface']}; color: {t['text']}; border: 1px solid {t['border']};
        border-radius: 8px; padding: 6px; selection-background-color: {t['accent_soft']};
        selection-color: {t['text']}; }}
    QPlainTextEdit#Log {{ background: {t['surface_alt']}; }}
    QTextBrowser {{ background: transparent; color: {t['text']}; border: none; padding: 0;
        selection-background-color: {t['accent_soft']}; selection-color: {t['text']}; }}
    QLabel#Kbd {{ background: {t['kbd_bg']}; color: {t['kbd_text']}; border: 1px solid {t['kbd_border']};
        border-radius: 4px; padding: 0 5px; }}

    /* tables and lists (cells are painted by the delegates in widgets.py) */
    QTableView {{ background: {t['surface']}; border: none; gridline-color: transparent;
        selection-background-color: {t['selection']}; selection-color: {t['selection_text']}; }}
    QHeaderView {{ background: {t['surface']}; border: none; }}
    QHeaderView::section {{ background: {t['surface']}; color: {t['text_muted']}; border: none;
        border-bottom: 1px solid {t['border']}; padding: 0 10px; min-height: 30px; }}
    QHeaderView::section:hover {{ color: {t['text']}; }}
    QHeaderView::up-arrow {{ image: {sort_down}; width: 12px; height: 12px; subcontrol-position: center right;
        padding-right: 6px; }}
    QHeaderView::down-arrow {{ image: {sort_up}; width: 12px; height: 12px; subcontrol-position: center right;
        padding-right: 6px; }}
    QTableCornerButton::section {{ background: {t['surface']}; border: none; }}
    QAbstractScrollArea::corner {{ background: transparent; border: none; }}
    QListView, QListWidget {{ background: transparent; border: none; color: {t['text']}; }}
    QScrollArea, QScrollArea > QWidget > QWidget#ScrollContent {{ background: transparent; border: none; }}

    QTabWidget::pane {{ border: none; top: 0; background: transparent; }}
    QTabBar {{ background: transparent; }}
    QTabBar::tab {{ background: transparent; color: {t['text_muted']}; border: 1px solid transparent;
        border-radius: 6px; padding: 4px 10px; margin: 0 4px 6px 0; }}
    QTabBar::tab:hover {{ color: {t['text']}; background: {t['hover']}; }}
    QTabBar::tab:selected {{ color: {t['text']}; background: {t['surface_alt']}; border-color: {t['border']}; }}
    QGroupBox {{ background: transparent; border: none; margin-top: 22px; padding: 0; }}
    QGroupBox::title {{ subcontrol-origin: margin; subcontrol-position: top left; left: 0; top: 0;
        color: {t['text_muted']}; }}

    QScrollBar:vertical {{ background: transparent; width: 10px; margin: 0; }}
    QScrollBar::handle:vertical {{ background: {t['scroll']}; border-radius: 3px; min-height: 32px; margin: 2px; }}
    QScrollBar::handle:vertical:hover {{ background: {t['scroll_hover']}; }}
    QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 0; }}
    QScrollBar::handle:horizontal {{ background: {t['scroll']}; border-radius: 3px; min-width: 32px; margin: 2px; }}
    QScrollBar::handle:horizontal:hover {{ background: {t['scroll_hover']}; }}
    QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; border: none; background: none; }}
    QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}
    QProgressBar {{ border: none; border-radius: 2px; background: {t['border']}; max-height: 4px; min-height: 4px; }}
    QProgressBar::chunk {{ background: {t['accent']}; border-radius: 2px; }}
    QSplitter {{ background: transparent; }}
    QSplitter::handle {{ background: transparent; }}
    QSplitter[line="true"]::handle {{ background: {t['border']}; }}
    QSplitter[line="true"]::handle:hover {{ background: {t['focus']}; }}
    QStatusBar {{ background: {t['bg']}; color: {t['text_muted']}; border: none; }}

    /* toast + command palette */
    QFrame#Toast {{ background: {t['raised']}; border: 1px solid {t['border_strong']}; border-radius: 8px; }}
    QFrame#Toast QLabel {{ background: transparent; color: {t['text']}; }}
    QWidget#PaletteScrim {{ background: {t['scrim']}; }}
    QFrame#PalettePanel {{ background: {t['raised']}; border: 1px solid {t['border_strong']}; border-radius: 12px; }}
    QLineEdit#PaletteInput {{ background: transparent; border: none; border-bottom: 1px solid {t['border']};
        border-radius: 0; padding: 0 16px; min-height: 50px; }}
    QListView#PaletteList {{ background: transparent; border: none; }}
    QFrame#PaletteFooter {{ background: transparent; border: none; border-top: 1px solid {t['border']}; }}
    """


class _PopupPolish(QObject):
    """Rounded corners for menus and tooltips: Qt paints popups as rectangles unless the window is
    translucent, so the stylesheet's border-radius would leave square corners behind."""

    def eventFilter(self, obj, event):
        if event.type() == QEvent.Polish and obj.isWidgetType() and not obj.property("_popup_polished"):
            if obj.inherits("QMenu") or obj.inherits("QTipLabel"):
                obj.setProperty("_popup_polished", True)
                obj.setWindowFlag(Qt.FramelessWindowHint, True)
                obj.setWindowFlag(Qt.NoDropShadowWindowHint, True)
                obj.setAttribute(Qt.WA_TranslucentBackground, True)
            elif obj.inherits("QComboBox") and not obj.property("_popup_polished"):
                from PySide6.QtWidgets import QStyledItemDelegate

                obj.setProperty("_popup_polished", True)
                obj.setItemDelegate(QStyledItemDelegate(obj))  # lets the stylesheet size popup rows
        return False


_polisher = []


def repolish(widget):
    """Re-apply the stylesheet after changing a dynamic property used in it (e.g. active=true)."""
    widget.style().unpolish(widget)
    widget.style().polish(widget)
    widget.update()


def apply(app, mode_name="system", presentation=None):
    """Apply the theme. mode_name: 'system' | 'light' | 'dark'."""
    app.setStyle("Fusion")
    if presentation is not None:
        _state["presentation"] = bool(presentation)
    if not _polisher:
        _polisher.append(_PopupPolish(app))
        app.installEventFilter(_polisher[0])
    load_fonts()
    hints = app.styleHints()
    if mode_name == "system":
        if hasattr(hints, "unsetColorScheme"):  # forget a Light/Dark choice forced earlier (Qt 6.8+)
            hints.unsetColorScheme()
        dark = hasattr(hints, "colorScheme") and hints.colorScheme() == Qt.ColorScheme.Dark
        resolved = "dark" if dark else "light"
    else:
        resolved = mode_name
        if hasattr(hints, "setColorScheme"):
            hints.setColorScheme(Qt.ColorScheme.Dark if resolved == "dark" else Qt.ColorScheme.Light)
    _state["mode"] = resolved
    app.setFont(font("body"))
    app.setPalette(palette(resolved))
    app.setStyleSheet(stylesheet(resolved))
    signals.changed.emit(resolved)
    return resolved
