"""Live analytics widgets for the Qt operator console."""

from __future__ import annotations

import math
import random
from collections import deque
from dataclasses import dataclass
from typing import Callable, Deque, Iterable, List, Optional, Sequence, Tuple

from PySide6.QtCharts import (
    QBarCategoryAxis,
    QBarSeries,
    QBarSet,
    QChart,
    QChartView,
    QScatterSeries,
    QValueAxis,
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QPainter, QVector3D
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .types import FlowSummary

try:  # Optional 3D visualization support
    from PySide6.QtDataVisualization import (
        Q3DScatter,
        QScatter3DSeries,
        QScatterDataItem,
        QValue3DAxis,
    )

    _HAS_DATAVIZ = True
except ImportError:  # pragma: no cover - optional dependency
    _HAS_DATAVIZ = False


@dataclass(frozen=True)
class MetricSpec:
    key: str
    label: str
    axis_label: str
    extractor: Callable[[FlowSummary], float]
    histogram_edges: Sequence[float]

    def category_labels(self) -> List[str]:
        labels: List[str] = []
        lower = 0.0
        for upper in self.histogram_edges:
            labels.append(_format_bucket(lower, upper))
            lower = upper
        labels.append(f"> {self.histogram_edges[-1]:g}")
        return labels


FEATURE_METRICS: Tuple[MetricSpec, ...] = (
    MetricSpec(
        key="duration",
        label="Duration",
        axis_label="Duration (s)",
        extractor=lambda flow: max(flow.duration_s, 0.0),
        histogram_edges=(0.5, 1.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0),
    ),
    MetricSpec(
        key="packets",
        label="Packets",
        axis_label="Packets",
        extractor=lambda flow: float(max(flow.packets, 0)),
        histogram_edges=(1, 5, 10, 20, 50, 100, 250, 500, 1000),
    ),
    MetricSpec(
        key="bytes",
        label="Bytes",
        axis_label="Bytes",
        extractor=lambda flow: float(max(flow.bytes, 0)),
        histogram_edges=(256, 1024, 4096, 16_384, 65_536, 262_144, 1_048_576, 4_194_304),
    ),
)

CLUSTER_COLORS = [
    QColor("#1f77b4"),
    QColor("#ff7f0e"),
    QColor("#2ca02c"),
    QColor("#d62728"),
    QColor("#9467bd"),
    QColor("#8c564b"),
    QColor("#e377c2"),
]


class FlowAnalyticsAggregator:
    """Keeps a bounded window of flow summaries for analytic visualizations."""

    def __init__(self, max_samples: int = 2000) -> None:
        self._flows: Deque[FlowSummary] = deque(maxlen=max_samples)

    def add_flow(self, summary: FlowSummary) -> None:
        self._flows.append(summary)

    def clear(self) -> None:
        self._flows.clear()

    def flows(self) -> List[FlowSummary]:
        return list(self._flows)


class FeatureHistogram(QChartView):
    """Displays histogram buckets for a selectable metric."""

    def __init__(self, parent=None) -> None:
        chart = QChart()
        chart.setTitle("Feature histogram")
        self._series = QBarSeries()
        chart.addSeries(self._series)

        self._axis_x = QBarCategoryAxis()
        chart.addAxis(self._axis_x, Qt.AlignBottom)
        self._series.attachAxis(self._axis_x)

        self._axis_y = QValueAxis()
        self._axis_y.setTitleText("Flows")
        self._axis_y.setLabelFormat("%d")
        chart.addAxis(self._axis_y, Qt.AlignLeft)
        self._series.attachAxis(self._axis_y)

        super().__init__(chart, parent)
        self.setRenderHint(QPainter.Antialiasing)
        self.setMinimumHeight(220)
        self._metric = FEATURE_METRICS[0]

    def set_metric(self, metric: MetricSpec) -> None:
        self._metric = metric
        self._axis_x.setTitleText(metric.axis_label)

    def update_data(self, flows: Iterable[FlowSummary]) -> None:
        edges = self._metric.histogram_edges
        buckets = [0 for _ in range(len(edges))]
        overflow = 0
        for flow in flows:
            value = self._metric.extractor(flow)
            placed = False
            for index, upper in enumerate(edges):
                if value <= upper:
                    buckets[index] += 1
                    placed = True
                    break
            if not placed:
                overflow += 1

        counts = buckets + [overflow]
        bar_set = QBarSet("Flows")
        bar_set.append(counts)

        self._series.clear()
        self._series.append(bar_set)

        self._axis_x.clear()
        self._axis_x.append(self._metric.category_labels())

        max_count = max(counts) if counts else 0
        self._axis_y.setRange(0, max(1, max_count))


class ClusterScatterPlot(QChartView):
    """Scatter plot that renders clusters as separate series."""

    def __init__(self, parent=None) -> None:
        chart = QChart()
        chart.setTitle("Feature scatter")
        chart.legend().setVisible(True)
        self._axis_x = QValueAxis()
        self._axis_y = QValueAxis()
        chart.addAxis(self._axis_x, Qt.AlignBottom)
        chart.addAxis(self._axis_y, Qt.AlignLeft)

        super().__init__(chart, parent)
        self.setRenderHint(QPainter.Antialiasing)
        self.setMinimumHeight(220)
        self._series: List[QScatterSeries] = []

    def set_axis_labels(self, x_label: str, y_label: str) -> None:
        self._axis_x.setTitleText(x_label)
        self._axis_y.setTitleText(y_label)

    def axis_labels(self) -> Tuple[str, str]:
        return (self._axis_x.titleText(), self._axis_y.titleText())

    def update_clusters(self, clusters: List[Tuple[str, List[Tuple[float, float]]]]) -> None:
        chart = self.chart()
        for series in self._series:
            chart.removeSeries(series)
        self._series.clear()

        all_points: List[Tuple[float, float]] = []
        for index, (label, points) in enumerate(clusters):
            color = CLUSTER_COLORS[index % len(CLUSTER_COLORS)]
            series = QScatterSeries()
            series.setName(label)
            series.setColor(color)
            series.setMarkerSize(8.0)
            for x, y in points:
                series.append(float(x), float(y))
                all_points.append((x, y))
            chart.addSeries(series)
            series.attachAxis(self._axis_x)
            series.attachAxis(self._axis_y)
            self._series.append(series)

        if not all_points:
            self._axis_x.setRange(0.0, 1.0)
            self._axis_y.setRange(0.0, 1.0)
            return

        max_x = max(point[0] for point in all_points)
        max_y = max(point[1] for point in all_points)
        self._axis_x.setRange(0.0, max(1.0, max_x * 1.05))
        self._axis_y.setRange(0.0, max(1.0, max_y * 1.05))


class FlowAnalyticsPane(QGroupBox):
    """Container widget wiring analytics charts to the aggregator."""

    cluster_selected = Signal(list)
    cluster_export_requested = Signal(list)

    def __init__(self, parent=None) -> None:
        super().__init__("Live Analytics", parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(12)

        self._aggregator = FlowAnalyticsAggregator()
        self._cluster_flow_sets: List[List[FlowSummary]] = []
        self._cluster_3d_data: List[Tuple[str, List[Tuple[float, float, float]]]] = []

        control_group = QWidget(self)
        control_layout = QFormLayout(control_group)
        control_layout.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)

        self.projection_mode_combo = QComboBox()
        self.projection_mode_combo.addItems([
            "Manual metrics",
            "PCA (packets & bytes)",
        ])

        self.histogram_metric_combo = QComboBox()
        for metric in FEATURE_METRICS:
            self.histogram_metric_combo.addItem(metric.label, metric)

        self.scatter_x_combo = QComboBox()
        self.scatter_y_combo = QComboBox()
        for metric in FEATURE_METRICS:
            self.scatter_x_combo.addItem(metric.label, metric)
            self.scatter_y_combo.addItem(metric.label, metric)
        self.scatter_x_combo.setCurrentIndex(1)  # Packets
        self.scatter_y_combo.setCurrentIndex(2)  # Bytes

        control_layout.addRow("Projection", self.projection_mode_combo)
        control_layout.addRow("Histogram metric", self.histogram_metric_combo)
        control_layout.addRow("Scatter X", self.scatter_x_combo)
        control_layout.addRow("Scatter Y", self.scatter_y_combo)

        layout.addWidget(control_group)

        chart_grid = QGridLayout()
        chart_grid.setContentsMargins(0, 0, 0, 0)
        chart_grid.setSpacing(12)

        self._histogram = FeatureHistogram(self)
        self._scatter = ClusterScatterPlot(self)
        chart_grid.addWidget(self._histogram, 0, 0)
        chart_grid.addWidget(self._scatter, 0, 1)
        charts_container = QWidget(self)
        charts_container.setLayout(chart_grid)
        layout.addWidget(charts_container)

        self.cluster_details = QTreeWidget()
        self.cluster_details.setColumnCount(5)
        self.cluster_details.setHeaderLabels([
            "Cluster",
            "Flows",
            "Avg Duration (s)",
            "Avg Packets",
            "Avg Bytes",
        ])
        self.cluster_details.setAlternatingRowColors(True)
        layout.addWidget(self.cluster_details)

        button_row = QHBoxLayout()
        self.cluster_export_button = QPushButton("Export Selected Cluster")
        self.cluster_3d_button = QPushButton("Open 3D View")
        self.cluster_export_button.setEnabled(False)
        self.cluster_3d_button.setEnabled(_HAS_DATAVIZ)
        if not _HAS_DATAVIZ:
            self.cluster_3d_button.setToolTip(
                "Qt Data Visualization is not available. Install PySide6[3d] to enable."
            )
        button_row.addWidget(self.cluster_export_button)
        button_row.addWidget(self.cluster_3d_button)
        button_row.addStretch(1)
        layout.addLayout(button_row)

        self.cluster_label = QLabel("Clusters: insufficient data")
        self.cluster_label.setWordWrap(True)
        layout.addWidget(self.cluster_label)

        self.projection_mode_combo.currentIndexChanged.connect(self._on_projection_changed)
        self.histogram_metric_combo.currentIndexChanged.connect(self._on_histogram_metric_changed)
        self.scatter_x_combo.currentIndexChanged.connect(self._on_scatter_metric_changed)
        self.scatter_y_combo.currentIndexChanged.connect(self._on_scatter_metric_changed)
        self.cluster_details.currentItemChanged.connect(self._on_cluster_item_changed)
        self.cluster_export_button.clicked.connect(self._on_cluster_export_clicked)
        self.cluster_3d_button.clicked.connect(self._open_3d_view)

        self._update_combobox_states()
        self._update_metrics()

    # ------------------------------------------------------------------
    def record_flow(self, summary: FlowSummary) -> None:
        self._aggregator.add_flow(summary)
        self._refresh_visuals()

    def reset(self) -> None:
        self._aggregator.clear()
        self._cluster_flow_sets = []
        self._cluster_3d_data = []
        self._histogram.update_data([])
        self._scatter.update_clusters([])
        self.cluster_details.clear()
        self.cluster_export_button.setEnabled(False)
        self.cluster_label.setText("Clusters: insufficient data")

    # ------------------------------------------------------------------
    def _on_projection_changed(self, _index: int) -> None:
        self._update_combobox_states()
        self._update_metrics()
        self._refresh_visuals()

    def _on_histogram_metric_changed(self, index: int) -> None:
        metric = self.histogram_metric_combo.itemData(index)
        if isinstance(metric, MetricSpec):
            self._histogram.set_metric(metric)
            self._refresh_visuals()

    def _on_scatter_metric_changed(self, _index: int) -> None:
        self._update_metrics()
        self._refresh_visuals()

    def _on_cluster_item_changed(
        self,
        current: Optional[QTreeWidgetItem],
        _previous: Optional[QTreeWidgetItem],
    ) -> None:
        flows = self._flows_for_item(current)
        if flows is not None:
            self.cluster_selected.emit(list(flows))
        self.cluster_export_button.setEnabled(bool(flows))

    def _on_cluster_export_clicked(self) -> None:
        flows = self._flows_for_item(self.cluster_details.currentItem())
        if flows:
            self.cluster_export_requested.emit(list(flows))

    def _open_3d_view(self) -> None:
        if not _HAS_DATAVIZ or not self._cluster_3d_data:
            return
        dialog = Cluster3DDialog(self._cluster_3d_data, self)
        dialog.exec()

    def _flows_for_item(self, item: Optional[QTreeWidgetItem]) -> Optional[List[FlowSummary]]:
        if item is None:
            return None
        cluster_index = item.data(0, Qt.UserRole)
        if isinstance(cluster_index, int) and 0 <= cluster_index < len(self._cluster_flow_sets):
            return self._cluster_flow_sets[cluster_index]
        return None

    # ------------------------------------------------------------------
    def _update_combobox_states(self) -> None:
        manual = self._projection_mode() == "manual"
        for combo in (self.scatter_x_combo, self.scatter_y_combo):
            combo.setEnabled(manual)

    def _projection_mode(self) -> str:
        return "pca" if self.projection_mode_combo.currentIndex() == 1 else "manual"

    def _update_metrics(self) -> None:
        histogram_metric = self.histogram_metric_combo.currentData()
        if isinstance(histogram_metric, MetricSpec):
            self._histogram.set_metric(histogram_metric)

        if self._projection_mode() == "manual":
            metric_x = self.scatter_x_combo.currentData()
            metric_y = self.scatter_y_combo.currentData()
            if not isinstance(metric_x, MetricSpec) or not isinstance(metric_y, MetricSpec):
                return
            if metric_x.key == metric_y.key:
                for metric in FEATURE_METRICS:
                    if metric.key != metric_x.key:
                        self.scatter_y_combo.blockSignals(True)
                        self.scatter_y_combo.setCurrentIndex(FEATURE_METRICS.index(metric))
                        self.scatter_y_combo.blockSignals(False)
                        metric_y = metric
                        break
            self._scatter.set_axis_labels(metric_x.axis_label, metric_y.axis_label)
        else:
            self._scatter.set_axis_labels("PC1", "PC2")

    # ------------------------------------------------------------------
    def _refresh_visuals(self) -> None:
        flows = self._aggregator.flows()
        if not flows:
            self.reset()
            return

        self._histogram.update_data(flows)

        if self._projection_mode() == "manual":
            metric_x = self.scatter_x_combo.currentData()
            metric_y = self.scatter_y_combo.currentData()
            if not isinstance(metric_x, MetricSpec) or not isinstance(metric_y, MetricSpec):
                return
            points = [
                (metric_x.extractor(flow), metric_y.extractor(flow))
                for flow in flows
            ]
        else:
            points, explained = _compute_pca_projection(flows)
            self._scatter.set_axis_labels(
                f"PC1 ({explained[0]:.0f}% var)",
                f"PC2 ({explained[1]:.0f}% var)",
            )

        cluster_points, cluster_indices = _cluster_points(points)
        if not cluster_points:
            self.reset()
            return

        self._scatter.update_clusters([
            (f"Cluster {i + 1} ({len(indices)} flows)", pts)
            for i, (pts, indices) in enumerate(zip(cluster_points, cluster_indices))
        ])

        self._cluster_flow_sets = [
            [flows[index] for index in indices]
            for indices in cluster_indices
        ]
        self._cluster_3d_data = [
            (
                f"Cluster {i + 1}",
                [
                    (
                        max(flow.duration_s, 0.0),
                        float(max(flow.packets, 0)),
                        float(max(flow.bytes, 0)),
                    )
                    for flow in flow_set
                ],
            )
            for i, flow_set in enumerate(self._cluster_flow_sets)
        ]

        self._update_cluster_details()

        lines = ["Clusters:"]
        axis_x, axis_y = self._scatter.axis_labels()
        for index, flow_set in enumerate(self._cluster_flow_sets, 1):
            if not flow_set:
                continue
            avg_packets = sum(flow.packets for flow in flow_set) / len(flow_set)
            avg_bytes = sum(flow.bytes for flow in flow_set) / len(flow_set)
            lines.append(
                f"  {index}: {len(flow_set)} flows (centroid {axis_x}≈{avg_packets:.1f}, {axis_y}≈{avg_bytes:.1f})"
            )
        self.cluster_label.setText("\n".join(lines))

    def _update_cluster_details(self) -> None:
        self.cluster_details.blockSignals(True)
        self.cluster_details.clear()
        for index, flow_set in enumerate(self._cluster_flow_sets):
            if not flow_set:
                continue
            avg_duration = sum(flow.duration_s for flow in flow_set) / len(flow_set)
            avg_packets = sum(flow.packets for flow in flow_set) / len(flow_set)
            avg_bytes = sum(flow.bytes for flow in flow_set) / len(flow_set)
            item = QTreeWidgetItem(
                [
                    f"Cluster {index + 1}",
                    str(len(flow_set)),
                    f"{avg_duration:.2f}",
                    f"{avg_packets:.1f}",
                    f"{avg_bytes:.1f}",
                ]
            )
            item.setData(0, Qt.UserRole, index)
            self.cluster_details.addTopLevelItem(item)

        self.cluster_details.blockSignals(False)
        if self.cluster_details.topLevelItemCount() > 0:
            self.cluster_details.setCurrentItem(self.cluster_details.topLevelItem(0))
        else:
            self.cluster_export_button.setEnabled(False)
            self.cluster_selected.emit([])


# ----------------------------------------------------------------------

def _cluster_points(
    points: List[Tuple[float, float]],
    k: int = 3,
) -> Tuple[List[List[Tuple[float, float]]], List[List[int]]]:
    annotated = [
        (index, point[0], point[1])
        for index, point in enumerate(points)
        if point[0] or point[1]
    ]
    if not annotated:
        return [], []

    target_k = min(k, len(annotated)) or 1
    centroids = [
        (annotated[idx][1], annotated[idx][2])
        for idx in random.sample(range(len(annotated)), target_k)
    ]

    for _ in range(15):
        assignments: List[List[Tuple[int, float, float]]] = [[] for _ in range(target_k)]
        for orig_index, x, y in annotated:
            distances = [
                (cx - x) ** 2 + (cy - y) ** 2
                for cx, cy in centroids
            ]
            closest = min(range(target_k), key=lambda idx_: distances[idx_])
            assignments[closest].append((orig_index, x, y))

        new_centroids: List[Tuple[float, float]] = []
        for cluster in assignments:
            if not cluster:
                new_centroids.append(random.choice(annotated)[1:])
                continue
            avg_x = sum(point[1] for point in cluster) / len(cluster)
            avg_y = sum(point[2] for point in cluster) / len(cluster)
            new_centroids.append((avg_x, avg_y))

        if all(
            math.isclose(cx, nx, rel_tol=1e-3) and math.isclose(cy, ny, rel_tol=1e-3)
            for (cx, cy), (nx, ny) in zip(centroids, new_centroids)
        ):
            centroids = new_centroids
            break
        centroids = new_centroids

    clusters_points = [
        [(point[1], point[2]) for point in cluster]
        for cluster in assignments
        if cluster
    ]
    clusters_indices = [
        [point[0] for point in cluster]
        for cluster in assignments
        if cluster
    ]

    if not clusters_points:
        clusters_points = [[(point[1], point[2]) for point in annotated]]
        clusters_indices = [[point[0] for point in annotated]]

    combined = sorted(
        zip(clusters_points, clusters_indices),
        key=lambda pair: len(pair[1]),
        reverse=True,
    )
    separated_points, separated_indices = zip(*combined)
    return list(separated_points), list(separated_indices)


def _format_bucket(lower: float, upper: float) -> str:
    if lower == 0.0:
        return f"≤ {upper:g}"
    return f"{lower:g}–{upper:g}"


def _compute_pca_projection(
    flows: List[FlowSummary],
) -> Tuple[List[Tuple[float, float]], Tuple[float, float]]:
    packets = [max(flow.packets, 0) for flow in flows]
    bytes_ = [max(flow.bytes, 0) for flow in flows]
    if len(packets) < 2:
        points = list(zip(packets, bytes_))
        return points, (0.0, 0.0)

    mean_packets = sum(packets) / len(packets)
    mean_bytes = sum(bytes_) / len(bytes_)
    centered = [
        (p - mean_packets, b - mean_bytes)
        for p, b in zip(packets, bytes_)
    ]

    cov_xx = sum(dx * dx for dx, _ in centered) / (len(centered) - 1)
    cov_yy = sum(dy * dy for _, dy in centered) / (len(centered) - 1)
    cov_xy = sum(dx * dy for dx, dy in centered) / (len(centered) - 1)

    trace = cov_xx + cov_yy
    det = cov_xx * cov_yy - cov_xy * cov_xy
    term = math.sqrt(max(trace * trace / 4 - det, 0.0))
    eigen1 = trace / 2 + term
    eigen2 = trace / 2 - term

    def _eigenvector(eigenvalue: float) -> Tuple[float, float]:
        if abs(cov_xy) > 1e-9:
            vec = (eigenvalue - cov_yy, cov_xy)
        elif cov_xx >= cov_yy:
            vec = (1.0, 0.0)
        else:
            vec = (0.0, 1.0)
        length = math.hypot(*vec)
        if length == 0:
            return (1.0, 0.0)
        return (vec[0] / length, vec[1] / length)

    v1 = _eigenvector(eigen1)
    v2 = _eigenvector(eigen2)

    points = [
        (
            dx * v1[0] + dy * v1[1],
            dx * v2[0] + dy * v2[1],
        )
        for dx, dy in centered
    ]

    total_var = eigen1 + eigen2 if (eigen1 + eigen2) > 0 else 1.0
    explained = (
        max(eigen1, 0.0) / total_var * 100.0,
        max(eigen2, 0.0) / total_var * 100.0,
    )

    return points, explained


def _centroid(points: List[Tuple[float, float]]) -> Tuple[float, float]:
    if not points:
        return (0.0, 0.0)
    sum_x = sum(point[0] for point in points)
    sum_y = sum(point[1] for point in points)
    return (sum_x / len(points), sum_y / len(points))


if _HAS_DATAVIZ:  # pragma: no cover - requires Qt Data Visualization

    class Cluster3DDialog(QDialog):
        def __init__(
            self,
            clusters: List[Tuple[str, List[Tuple[float, float, float]]]],
            parent=None,
        ) -> None:
            super().__init__(parent)
            self.setWindowTitle("Cluster 3D Scatter")
            self.resize(720, 520)

            scatter = Q3DScatter()
            scatter.setShadowQuality(Q3DScatter.ShadowQualityNone)

            axis_x = QValue3DAxis()
            axis_x.setTitle("Duration (s)")
            axis_x.setLabelFormat("%.1f")
            scatter.setAxisX(axis_x)

            axis_y = QValue3DAxis()
            axis_y.setTitle("Packets")
            axis_y.setLabelFormat("%.1f")
            scatter.setAxisY(axis_y)

            axis_z = QValue3DAxis()
            axis_z.setTitle("Bytes")
            axis_z.setLabelFormat("%.1f")
            scatter.setAxisZ(axis_z)

            max_duration = max((point[0] for _, pts in clusters for point in pts), default=1.0)
            max_packets = max((point[1] for _, pts in clusters for point in pts), default=1.0)
            max_bytes = max((point[2] for _, pts in clusters for point in pts), default=1.0)

            axis_x.setRange(0.0, max_duration * 1.1)
            axis_y.setRange(0.0, max_packets * 1.1)
            axis_z.setRange(0.0, max_bytes * 1.1)

            for label, points in clusters:
                if not points:
                    continue
                series = QScatter3DSeries()
                series.setName(label)
                series.setItemLabelFormat("@seriesName - (@xLabel, @yLabel, @zLabel)")
                data_items = [
                    QScatterDataItem(QVector3D(point[0], point[1], point[2]))
                    for point in points
                ]
                series.dataProxy().resetArray(data_items)
                scatter.addSeries(series)

            container = QWidget.createWindowContainer(scatter)
            layout = QVBoxLayout(self)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.addWidget(container)

else:  # pragma: no cover - graceful fallback

    class Cluster3DDialog:  # type: ignore[override]
        def __init__(self, *_args, **_kwargs) -> None:
            raise RuntimeError("Qt Data Visualization is not available")


__all__ = ["FlowAnalyticsPane", "FlowAnalyticsAggregator"]
