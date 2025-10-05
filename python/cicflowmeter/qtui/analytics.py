"""Live analytics widgets for the Qt operator console."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Callable, Deque, Dict, Iterable, List, Optional, Sequence, Tuple

import numpy as np
from PySide6.QtCharts import (
    QBarCategoryAxis,
    QBarSeries,
    QBarSet,
    QChart,
    QChartView,
    QDateTimeAxis,
    QLineSeries,
    QScatterSeries,
    QValueAxis,
)
from PySide6.QtCore import Qt, Signal, QDateTime, QPointF
from PySide6.QtGui import QColor, QPainter, QVector3D
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDoubleSpinBox,
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
from ..clustering import (
    ClusterResult,
    ClusterSummary,
    FlowClusterer,
    dataset_from_matrix,
    summarize_clusters,
)

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


class FlowTimelineChart(QChartView):
    """Shows flow arrival counts over a rolling window."""

    def __init__(self, parent=None, bucket_seconds: int = 30) -> None:
        self._bucket_seconds = max(1, bucket_seconds)

        chart = QChart()
        chart.setTitle("Flow timeline")
        self._series = QLineSeries()
        self._series.setName("Flows")
        chart.addSeries(self._series)
        chart.legend().setVisible(False)

        self._axis_x = QDateTimeAxis()
        self._axis_x.setTitleText("Time")
        self._axis_x.setFormat("HH:mm:ss")
        chart.addAxis(self._axis_x, Qt.AlignBottom)
        self._series.attachAxis(self._axis_x)

        self._axis_y = QValueAxis()
        self._axis_y.setTitleText("Flows per interval")
        self._axis_y.setLabelFormat("%d")
        chart.addAxis(self._axis_y, Qt.AlignLeft)
        self._series.attachAxis(self._axis_y)

        super().__init__(chart, parent)
        self.setRenderHint(QPainter.Antialiasing)
        self.setMinimumHeight(200)
        self.clear()

    def clear(self) -> None:
        self._series.clear()
        now = QDateTime.currentDateTime()
        self._axis_x.setRange(now.addSecs(-5 * self._bucket_seconds), now)
        self._axis_y.setRange(0, 1)

    def update_data(self, flows: Sequence[FlowSummary]) -> None:
        if not flows:
            self.clear()
            return

        bucket_ms = self._bucket_seconds * 1000
        buckets: Dict[int, int] = {}

        for flow in flows:
            timestamp_ms = max(flow.start_micros // 1000, 0)
            bucket = (timestamp_ms // bucket_ms) * bucket_ms
            buckets[bucket] = buckets.get(bucket, 0) + 1

        points = [
            QPointF(bucket, count)
            for bucket, count in sorted(buckets.items())
        ]

        if not points:
            self.clear()
            return

        self._series.replace(points)
        start_dt = QDateTime.fromMSecsSinceEpoch(int(points[0].x()))
        end_dt = QDateTime.fromMSecsSinceEpoch(int(points[-1].x()))
        if start_dt == end_dt:
            end_dt = end_dt.addSecs(self._bucket_seconds)
        self._axis_x.setRange(start_dt, end_dt)

        max_count = max(point.y() for point in points)
        self._axis_y.setRange(0, max(1.0, max_count * 1.1))


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
        self._cluster_summaries: List[Optional[ClusterSummary]] = []
        self._cluster_axis_labels: Tuple[str, str] = ("", "")

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

        self.anomaly_threshold_spin = QDoubleSpinBox()
        self.anomaly_threshold_spin.setRange(0.5, 5.0)
        self.anomaly_threshold_spin.setSingleStep(0.5)
        self.anomaly_threshold_spin.setValue(2.0)

        control_layout.addRow("Projection", self.projection_mode_combo)
        control_layout.addRow("Histogram metric", self.histogram_metric_combo)
        control_layout.addRow("Scatter X", self.scatter_x_combo)
        control_layout.addRow("Scatter Y", self.scatter_y_combo)
        control_layout.addRow("Anomaly σ", self.anomaly_threshold_spin)

        layout.addWidget(control_group)

        chart_grid = QGridLayout()
        chart_grid.setContentsMargins(0, 0, 0, 0)
        chart_grid.setSpacing(12)

        self._histogram = FeatureHistogram(self)
        self._scatter = ClusterScatterPlot(self)
        self._timeline = FlowTimelineChart(self)
        chart_grid.addWidget(self._histogram, 0, 0)
        chart_grid.addWidget(self._scatter, 0, 1)
        chart_grid.addWidget(self._timeline, 1, 0, 1, 2)
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

        self.anomaly_list = QTreeWidget()
        self.anomaly_list.setColumnCount(6)
        self.anomaly_list.setHeaderLabels(
            [
                "Flow ID",
                "Cluster",
                "Distance",
                "Z-Score",
                "Packets",
                "Bytes",
            ]
        )
        self.anomaly_list.setRootIsDecorated(False)
        self.anomaly_list.setAlternatingRowColors(True)
        layout.addWidget(self.anomaly_list)

        self.anomaly_label = QLabel("Anomalies: none")
        self.anomaly_label.setWordWrap(True)
        layout.addWidget(self.anomaly_label)

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
        self.anomaly_threshold_spin.valueChanged.connect(lambda _value: self._refresh_visuals())

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
        self._cluster_summaries = []
        self._cluster_axis_labels = ("", "")
        self._histogram.update_data([])
        self._scatter.update_clusters([])
        self._timeline.clear()
        self.cluster_details.clear()
        self.cluster_export_button.setEnabled(False)
        self.cluster_label.setText("Clusters: insufficient data")
        self.anomaly_list.clear()
        self.anomaly_label.setText("Anomalies: none")

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

        self._timeline.update_data(flows)
        self._histogram.update_data(flows)

        if self._projection_mode() == "manual":
            metric_x = self.scatter_x_combo.currentData()
            metric_y = self.scatter_y_combo.currentData()
            if not isinstance(metric_x, MetricSpec) or not isinstance(metric_y, MetricSpec):
                return

            annotated = [
                (index, metric_x.extractor(flow), metric_y.extractor(flow))
                for index, flow in enumerate(flows)
                if metric_x.extractor(flow) or metric_y.extractor(flow)
            ]
            if not annotated:
                self.reset()
                return

            index_map = [entry[0] for entry in annotated]
            matrix = np.asarray([[entry[1], entry[2]] for entry in annotated], dtype=float)
            dataset = dataset_from_matrix(matrix, (metric_x.key, metric_y.key))
            clusterer = FlowClusterer(dataset)
            clusterer.build_raw()
            result = clusterer.raw_result()
            if result is None:
                self.reset()
                return
            feature_matrix = np.asarray(result.projection, dtype=float)
            (
                cluster_points,
                cluster_indices,
                cluster_rows,
                cluster_labels,
            ) = _clusters_from_result(result, index_map)
            axis_x_label = metric_x.axis_label
            axis_y_label = metric_y.axis_label
        else:
            dataset = _dataset_from_flows(flows)
            if dataset is None or not dataset.has_numeric_data():
                self.reset()
                return

            clusterer = FlowClusterer(dataset)
            clusterer.build_with_dimensionality_reduction()
            projection = clusterer.reduced_projection()
            result = clusterer.reduced_result()
            if projection is None or result is None:
                self.reset()
                return

            explained = projection.explained_variance_ratio
            axis_x_label = _pc_axis_label("PC1", explained, 0)
            axis_y_label = _pc_axis_label("PC2", explained, 1)
            index_map = list(range(len(flows)))
            feature_matrix = np.asarray(result.projection, dtype=float)
            (
                cluster_points,
                cluster_indices,
                cluster_rows,
                cluster_labels,
            ) = _clusters_from_result(result, index_map)

        if not cluster_points:
            self.reset()
            return

        self._cluster_axis_labels = (axis_x_label, axis_y_label)
        self._scatter.set_axis_labels(axis_x_label, axis_y_label)

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

        self._cluster_summaries = []
        if result is not None:
            summaries = summarize_clusters(result, self._cluster_axis_labels)
            summary_map = {summary.cluster_label: summary for summary in summaries}
            self._cluster_summaries = [summary_map.get(label) for label in cluster_labels]

        self._update_anomalies(feature_matrix, cluster_indices, cluster_rows, flows)

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
            if index < len(self._cluster_summaries):
                summary = self._cluster_summaries[index]
                if summary is not None:
                    tooltip_lines = []
                    for axis_idx, axis_label in enumerate(self._cluster_axis_labels):
                        if axis_idx >= len(summary.centroid):
                            break
                        tooltip_lines.append(
                            f"{axis_label}: μ={summary.centroid[axis_idx]:.2f}, σ={summary.stdev[axis_idx]:.2f}"
                        )
                    if tooltip_lines:
                        item.setToolTip(0, "\n".join(tooltip_lines))
            self.cluster_details.addTopLevelItem(item)

        self.cluster_details.blockSignals(False)
        if self.cluster_details.topLevelItemCount() > 0:
            self.cluster_details.setCurrentItem(self.cluster_details.topLevelItem(0))
        else:
            self.cluster_export_button.setEnabled(False)
            self.cluster_selected.emit([])

    def _update_anomalies(
        self,
        matrix: np.ndarray,
        cluster_indices: Sequence[Sequence[int]],
        cluster_rows: Sequence[Sequence[int]],
        flows: Sequence[FlowSummary],
    ) -> None:
        self.anomaly_list.blockSignals(True)
        self.anomaly_list.clear()

        if matrix.ndim == 1:
            matrix = np.atleast_2d(matrix)
        if matrix.shape[0] == 0:
            self.anomaly_label.setText("Anomalies: none")
            self.anomaly_list.blockSignals(False)
            return

        if matrix.shape[1] < 2:
            padding = np.zeros((matrix.shape[0], 2 - matrix.shape[1]))
            matrix = np.hstack([matrix, padding])
        elif matrix.shape[1] > 2:
            matrix = matrix[:, :2]

        threshold = float(self.anomaly_threshold_spin.value())
        anomalies: List[Tuple[float, float, int, FlowSummary]] = []

        for cluster_idx, rows in enumerate(cluster_rows):
            if not rows:
                continue
            points = matrix[list(rows)]
            if points.shape[0] < 3:
                # Too few samples to gauge variance reliably.
                continue

            centroid = points.mean(axis=0)
            distances = np.linalg.norm(points - centroid, axis=1)
            mean_distance = float(distances.mean())
            std_distance = float(distances.std(ddof=1)) if points.shape[0] > 1 else 0.0
            if std_distance <= 1e-9:
                continue

            limit = mean_distance + threshold * std_distance

            for local_index, distance in enumerate(distances):
                if distance <= limit:
                    continue

                flow_index = cluster_indices[cluster_idx][local_index]
                if not (0 <= flow_index < len(flows)):
                    continue
                flow = flows[flow_index]
                z_score = (distance - mean_distance) / std_distance if std_distance > 0 else 0.0
                anomalies.append((distance, z_score, cluster_idx, flow))

        if anomalies:
            anomalies.sort(key=lambda item: item[1], reverse=True)
            max_rows = 50
            for distance, z_score, cluster_idx, flow in anomalies[:max_rows]:
                item = QTreeWidgetItem(
                    [
                        flow.flow_id,
                        f"{cluster_idx + 1}",
                        f"{distance:.2f}",
                        f"{z_score:.2f}",
                        str(flow.packets),
                        str(flow.bytes),
                    ]
                )
                self.anomaly_list.addTopLevelItem(item)
            self.anomaly_label.setText(
                f"Anomalies: {len(anomalies)} flagged (σ > {threshold:g})"
            )
        else:
            self.anomaly_label.setText("Anomalies: none")

        self.anomaly_list.blockSignals(False)


# ----------------------------------------------------------------------


def _clusters_from_result(
    result: Optional[ClusterResult],
    index_map: Sequence[int],
) -> Tuple[List[List[Tuple[float, float]]], List[List[int]], List[List[int]], List[int]]:
    if result is None:
        return [], [], [], []

    projection = np.asarray(result.projection)
    labels = np.asarray(result.labels, dtype=int)
    if projection.size == 0 or projection.shape[0] == 0:
        return [], [], [], []

    if projection.shape[1] < 2:
        zeros = np.zeros((projection.shape[0], 2 - projection.shape[1]))
        projection = np.hstack([projection, zeros])
    elif projection.shape[1] > 2:
        projection = projection[:, :2]

    clusters_points: List[List[Tuple[float, float]]] = []
    clusters_indices: List[List[int]] = []
    clusters_rows: List[List[int]] = []
    clusters_labels: List[int] = []

    unique_labels = sorted(set(labels.tolist()))
    for cluster_label in unique_labels:
        member_positions = [idx for idx, label in enumerate(labels) if label == cluster_label]
        if not member_positions:
            continue
        pts = [
            (
                float(projection[pos, 0]),
                float(projection[pos, 1]),
            )
            for pos in member_positions
        ]
        clusters_points.append(pts)
        clusters_indices.append([index_map[pos] for pos in member_positions])
        clusters_rows.append(member_positions)
        clusters_labels.append(cluster_label)

    if not clusters_points:
        fallback_points = [
            (
                float(point[0]),
                float(point[1]) if projection.shape[1] > 1 else 0.0,
            )
            for point in projection
        ]
        return [fallback_points], [list(index_map)], [list(range(len(index_map)))], [0]

    combined = sorted(
        zip(clusters_points, clusters_indices, clusters_rows, clusters_labels),
        key=lambda trio: len(trio[1]),
        reverse=True,
    )

    separated_points, separated_indices, separated_rows, separated_labels = zip(*combined)
    return (
        list(separated_points),
        list(separated_indices),
        list(separated_rows),
        list(separated_labels),
    )


def _dataset_from_flows(flows: Sequence[FlowSummary]) -> Optional["FlowDataset"]:
    if not flows:
        return None

    matrix = np.asarray(
        [
            (
                max(flow.duration_s, 0.0),
                float(max(flow.packets, 0)),
                float(max(flow.bytes, 0)),
            )
            for flow in flows
        ],
        dtype=float,
    )
    column_names = ("duration", "packets", "bytes")
    return dataset_from_matrix(matrix, column_names)


def _pc_axis_label(name: str, explained: Sequence[float], index: int) -> str:
    if index < len(explained) and explained[index] > 0:
        return f"{name} ({explained[index] * 100:.0f}% var)"
    return name


def _format_bucket(lower: float, upper: float) -> str:
    if lower == 0.0:
        return f"≤ {upper:g}"
    return f"{lower:g}–{upper:g}"


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
