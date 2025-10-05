"""Flow rate visualization widgets for the Qt operator console."""

from __future__ import annotations

from collections import deque
from typing import Deque, Iterable, List, Tuple

from PySide6.QtCharts import QChart, QChartView, QDateTimeAxis, QLineSeries, QValueAxis
from PySide6.QtCore import QDateTime, QPointF, Qt
from PySide6.QtGui import QPainter

from .types import FlowSummary

_MICROS_PER_SECOND = 1_000_000


class FlowRateAggregator:
    """Maintains a sliding window of flow counts grouped per second."""

    def __init__(self, window_seconds: int = 300) -> None:
        self.window_seconds = window_seconds
        self._buckets: Deque[Tuple[int, int]] = deque()

    def add_timestamp(self, start_micros: int) -> None:
        """Record a flow that started at the given microsecond timestamp."""
        second = start_micros // _MICROS_PER_SECOND
        if self._buckets and self._buckets[-1][0] == second:
            ts, count = self._buckets[-1]
            self._buckets[-1] = (ts, count + 1)
        else:
            self._buckets.append((second, 1))
        self._trim(second)

    def points(self) -> List[Tuple[int, int]]:
        return list(self._buckets)

    def clear(self) -> None:
        self._buckets.clear()

    # ------------------------------------------------------------------
    def _trim(self, latest_second: int) -> None:
        cutoff = latest_second - self.window_seconds
        while self._buckets and self._buckets[0][0] < cutoff:
            self._buckets.popleft()


class FlowRateChart(QChartView):
    """Qt Charts view that renders the flow-per-second series."""

    def __init__(self, *, window_seconds: int = 300, parent=None) -> None:
        self._aggregator = FlowRateAggregator(window_seconds)

        chart = QChart()
        chart.setTitle("Flows per second (sliding window)")

        self._series = QLineSeries()
        self._series.setName("Flows")
        chart.addSeries(self._series)

        self._axis_x = QDateTimeAxis()
        self._axis_x.setFormat("hh:mm:ss")
        self._axis_x.setTitleText("Start time")
        chart.addAxis(self._axis_x, Qt.AlignBottom)
        self._series.attachAxis(self._axis_x)

        self._axis_y = QValueAxis()
        self._axis_y.setLabelFormat("%d")
        self._axis_y.setTitleText("Flows")
        self._axis_y.setRange(0, 1)
        chart.addAxis(self._axis_y, Qt.AlignLeft)
        self._series.attachAxis(self._axis_y)

        super().__init__(chart, parent)
        self.setRenderHint(QPainter.Antialiasing)
        self.setMinimumHeight(220)

    # ------------------------------------------------------------------
    def record_flow(self, summary: FlowSummary) -> None:
        self._aggregator.add_timestamp(summary.start_micros)
        self._refresh_chart()

    def reset(self) -> None:
        self._aggregator.clear()
        self._series.clear()

    # ------------------------------------------------------------------
    def _refresh_chart(self) -> None:
        buckets = self._aggregator.points()
        if not buckets:
            self._series.clear()
            return

        points = [QPointF(float(second * 1000), float(count)) for second, count in buckets]
        self._series.replace(points)

        first_second = buckets[0][0]
        last_second = buckets[-1][0]
        start_dt = QDateTime.fromSecsSinceEpoch(first_second)
        end_dt = QDateTime.fromSecsSinceEpoch(last_second + 1)
        self._axis_x.setRange(start_dt, end_dt)

        max_count = max(count for _, count in buckets)
        upper = max(1, max_count + 1)
        self._axis_y.setRange(0, upper)


__all__ = ["FlowRateAggregator", "FlowRateChart"]
