"""QtCharts in the app's quiet style: no backgrounds, muted labels, horizontal gridlines only."""

from PySide6.QtCharts import QAbstractBarSeries, QChart, QChartView, QDateTimeAxis, QValueAxis
from PySide6.QtCore import QMargins, QRectF, Qt
from PySide6.QtGui import QColor, QImage, QPainter, QPen

from tenable_net.gui import theme


def chart_view(min_height=240, fixed_height=None):
    view = QChartView()
    view.setRenderHint(QPainter.Antialiasing)
    view.setStyleSheet("background: transparent; border: none;")
    view.setFrameShape(QChartView.NoFrame)
    if fixed_height:
        view.setFixedHeight(fixed_height)
    else:
        view.setMinimumHeight(min_height)
    return view


def style_chart(chart, mode_name=None, animate=True):
    """Apply theme colours and fonts to a chart and its axes (call again after a theme change)."""
    t = theme.tokens(mode_name)
    chart.setBackgroundVisible(False)
    chart.setPlotAreaBackgroundVisible(False)
    chart.setBackgroundRoundness(0)
    chart.setMargins(QMargins(0, 6, 0, 0))
    chart.layout().setContentsMargins(0, 0, 0, 0)
    legend = chart.legend()
    legend.setLabelColor(QColor(t["text_muted"]))
    legend.setFont(theme.font("caption"))
    legend.setMarkerShape(legend.MarkerShape.MarkerShapeCircle)
    chart.setAnimationOptions(QChart.SeriesAnimations if animate else QChart.NoAnimation)
    chart.setAnimationDuration(450)
    for axis in chart.axes():
        axis.setLabelsColor(QColor(t["text_muted"]))
        axis.setLabelsFont(theme.font("caption"))
        axis.setTitleBrush(QColor(t["text_muted"]))
        axis.setTitleFont(theme.font("caption"))
        axis.setGridLineColor(QColor(t["divider"]))
        axis.setMinorGridLineVisible(False)
        axis.setLinePen(QPen(QColor(t["border_strong"]), 1))
        if isinstance(axis, QValueAxis):  # values: gridlines, no axis line
            axis.setLineVisible(False)
            axis.setGridLineVisible(True)
        else:  # categories / dates: a baseline, no gridlines
            axis.setLineVisible(True)
            axis.setGridLineVisible(False)
    for series in chart.series():
        if isinstance(series, QAbstractBarSeries) and series.isLabelsVisible() \
                and series.labelsPosition() == QAbstractBarSeries.LabelsPosition.LabelsOutsideEnd:
            for bar in series.barSets():
                bar.setLabelColor(QColor(t["text_muted"]))
    return chart


def restyle(*views):
    for view in views:
        if view.chart() is not None:
            style_chart(view.chart())


def color(hex_color, alpha=None):
    c = QColor(hex_color)
    if alpha is not None:
        c.setAlphaF(alpha)
    return c


def no_border(barset, hex_color):
    barset.setColor(QColor(hex_color))
    barset.setBorderColor(QColor(hex_color))
    pen = barset.pen()
    pen.setStyle(Qt.NoPen)
    barset.setPen(pen)
    return barset


def render_image(view, width=480, height=280, ratio=2.0):
    """The view's chart drawn at a fixed size in light colours, without animation (for the PDF summary).
    Renders the chart's scene directly, so it works for views that are hidden or held by a layout."""
    chart = view.chart()
    old_geometry = chart.geometry()
    date_axes = [(axis, axis.tickCount()) for axis in chart.axes() if isinstance(axis, QDateTimeAxis)]
    for axis, _count in date_axes:
        axis.setTickCount(5)
    style_chart(chart, mode_name="light", animate=False)
    chart.setGeometry(QRectF(0, 0, width, height))
    image = QImage(round(width * ratio), round(height * ratio), QImage.Format_ARGB32_Premultiplied)
    image.setDevicePixelRatio(ratio)
    image.fill(Qt.white)
    painter = QPainter(image)
    painter.setRenderHint(QPainter.Antialiasing)
    chart.scene().render(painter, QRectF(0, 0, width, height), QRectF(0, 0, width, height))
    painter.end()
    chart.setGeometry(old_geometry)
    for axis, count in date_axes:
        axis.setTickCount(count)
    style_chart(chart)
    return image
