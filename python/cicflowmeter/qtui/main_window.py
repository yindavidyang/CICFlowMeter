"""Main Qt window for the CICFlowMeter operator console."""

from __future__ import annotations

import csv
import logging
import socket
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from PySide6.QtCore import Qt, QUrl, QItemSelectionModel
from PySide6.QtGui import QCloseEvent, QDesktopServices
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QTableView,
    QTabWidget,
    QVBoxLayout,
    QWidget,
    QHeaderView,
    QFileDialog,
    QProgressBar,
)

from .flow_model import FlowTableModel
from .live_capture import CaptureOptions, QtLiveCaptureBridge
from .types import FlowSummary
from .flow_rate import FlowRateChart
from .batch_runner import BatchJobRunner, BatchOptions
from .analytics import FlowAnalyticsPane
from .batch_history import BatchPreset, add_entry, load_history, save_history
from .batch_outputs import BatchOutputRecord, add_outputs, load_outputs, save_outputs

logger = logging.getLogger(__name__)


class MainWindow(QMainWindow):
    """Top-level window wiring the live capture controls and future tooling."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("CICFlowMeter Operator Console")
        self.resize(1100, 700)

        self._capture_bridge = QtLiveCaptureBridge(self)
        self._flow_model = FlowTableModel(max_rows=500, parent=self)
        self.flow_rate_chart = FlowRateChart(window_seconds=300, parent=self)
        self.batch_runner = BatchJobRunner(self)
        self.analytics_pane = FlowAnalyticsPane(self)
        self.analytics_pane.cluster_selected.connect(self._on_cluster_selected)
        self.analytics_pane.cluster_export_requested.connect(self._on_cluster_export)
        self._total_flows = 0
        self._last_batch_output: str | None = None
        self._batch_history: List[BatchPreset] = load_history()
        self._recent_outputs: List[BatchOutputRecord] = load_outputs()
        self._active_batch_preset: Optional[BatchPreset] = None

        self._setup_ui()
        self._connect_signals()
        self._populate_interfaces()
        self._refresh_history_list()
        self._refresh_output_list()

    # ------------------------------------------------------------------
    def _setup_ui(self) -> None:
        tab_widget = QTabWidget(self)
        tab_widget.addTab(self._build_live_capture_tab(), "Live Capture")
        tab_widget.addTab(self._build_batch_tab(), "Batch Tools")
        self.setCentralWidget(tab_widget)

    def _build_live_capture_tab(self) -> QWidget:
        container = QWidget(self)
        layout = QVBoxLayout(container)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        self.interface_combo = QComboBox()
        self.interface_combo.setEditable(True)
        self.filter_line = QLineEdit()
        self.filter_line.setPlaceholderText("Optional BPF filter expression (e.g. tcp port 80)")

        self.bidirectional_box = QCheckBox("Bidirectional flows")
        self.bidirectional_box.setChecked(True)

        self.ipv4_box = QCheckBox("IPv4")
        self.ipv4_box.setChecked(True)

        self.ipv6_box = QCheckBox("IPv6")
        self.ipv6_box.setChecked(False)

        self.flow_timeout_spin = QDoubleSpinBox()
        self.flow_timeout_spin.setRange(1.0, 3600.0)
        self.flow_timeout_spin.setValue(120.0)
        self.flow_timeout_spin.setSuffix(" s")
        self.flow_timeout_spin.setDecimals(1)

        self.activity_timeout_spin = QDoubleSpinBox()
        self.activity_timeout_spin.setRange(0.1, 600.0)
        self.activity_timeout_spin.setValue(5.0)
        self.activity_timeout_spin.setSuffix(" s")
        self.activity_timeout_spin.setDecimals(1)

        self.start_button = QPushButton("Start Capture")
        self.stop_button = QPushButton("Stop")
        self.stop_button.setEnabled(False)

        controls_group = QGroupBox("Capture Configuration")
        controls_layout = QFormLayout(controls_group)
        controls_layout.addRow("Interface", self.interface_combo)
        controls_layout.addRow("BPF Filter", self.filter_line)
        controls_layout.addRow("Flow Direction", self.bidirectional_box)

        protocol_row = QHBoxLayout()
        protocol_row.addWidget(self.ipv4_box)
        protocol_row.addWidget(self.ipv6_box)
        protocol_row.addStretch(1)
        controls_layout.addRow("Protocols", protocol_row)

        controls_layout.addRow("Flow Timeout", self.flow_timeout_spin)
        controls_layout.addRow("Activity Timeout", self.activity_timeout_spin)

        button_row = QHBoxLayout()
        button_row.addWidget(self.start_button)
        button_row.addWidget(self.stop_button)
        button_row.addStretch(1)
        controls_layout.addRow(button_row)

        layout.addWidget(controls_group)

        status_row = QHBoxLayout()
        self.status_label = QLabel("Status: idle")
        self.flow_count_label = QLabel("Flows captured: 0")
        status_row.addWidget(self.status_label)
        status_row.addStretch(1)
        status_row.addWidget(self.flow_count_label)
        layout.addLayout(status_row)

        self.flow_table = QTableView()
        self.flow_table.setModel(self._flow_model)
        self.flow_table.verticalHeader().setVisible(False)
        self.flow_table.setSelectionBehavior(QTableView.SelectRows)
        self.flow_table.setAlternatingRowColors(True)
        header: QHeaderView = self.flow_table.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.resizeSection(0, 180)
        header.resizeSection(1, 160)
        layout.addWidget(self.flow_table, stretch=2)

        chart_group = QGroupBox("Flow Rate")
        chart_layout = QVBoxLayout(chart_group)
        chart_layout.setContentsMargins(8, 8, 8, 8)
        chart_layout.addWidget(self.flow_rate_chart)
        layout.addWidget(chart_group, stretch=1)

        layout.addWidget(self.analytics_pane, stretch=1)

        self.log_output = QPlainTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setPlaceholderText("Status messages will appear here.")
        self.log_output.setMaximumBlockCount(500)
        layout.addWidget(self.log_output, stretch=1)

        return container

    def _build_batch_tab(self) -> QWidget:
        container = QWidget(self)
        layout = QVBoxLayout(container)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        form_group = QGroupBox("Batch Job Configuration")
        form_layout = QFormLayout(form_group)

        self.batch_input_line = QLineEdit()
        self.batch_input_line.setPlaceholderText("PCAP file or directory")
        input_buttons = QHBoxLayout()
        self.batch_input_file_button = QPushButton("Browse File…")
        self.batch_input_dir_button = QPushButton("Browse Folder…")
        input_buttons.addWidget(self.batch_input_line, stretch=1)
        input_buttons.addWidget(self.batch_input_file_button)
        input_buttons.addWidget(self.batch_input_dir_button)
        form_layout.addRow("PCAP source", input_buttons)

        self.batch_output_line = QLineEdit()
        self.batch_output_line.setPlaceholderText("Output directory for *_Flow.csv files")
        output_row = QHBoxLayout()
        self.batch_output_button = QPushButton("Browse…")
        output_row.addWidget(self.batch_output_line, stretch=1)
        output_row.addWidget(self.batch_output_button)
        form_layout.addRow("Output directory", output_row)

        self.batch_bidirectional_box = QCheckBox("Bidirectional flows")
        self.batch_bidirectional_box.setChecked(True)
        form_layout.addRow("Flow direction", self.batch_bidirectional_box)

        protocol_row = QHBoxLayout()
        self.batch_ipv4_box = QCheckBox("IPv4")
        self.batch_ipv4_box.setChecked(True)
        self.batch_ipv6_box = QCheckBox("IPv6")
        protocol_row.addWidget(self.batch_ipv4_box)
        protocol_row.addWidget(self.batch_ipv6_box)
        protocol_row.addStretch(1)
        form_layout.addRow("Protocols", protocol_row)

        self.batch_flow_timeout_spin = QDoubleSpinBox()
        self.batch_flow_timeout_spin.setRange(1.0, 7200.0)
        self.batch_flow_timeout_spin.setValue(120.0)
        self.batch_flow_timeout_spin.setSuffix(" s")
        self.batch_flow_timeout_spin.setDecimals(1)
        form_layout.addRow("Flow timeout", self.batch_flow_timeout_spin)

        self.batch_activity_timeout_spin = QDoubleSpinBox()
        self.batch_activity_timeout_spin.setRange(0.1, 600.0)
        self.batch_activity_timeout_spin.setValue(5.0)
        self.batch_activity_timeout_spin.setSuffix(" s")
        self.batch_activity_timeout_spin.setDecimals(1)
        form_layout.addRow("Activity timeout", self.batch_activity_timeout_spin)

        layout.addWidget(form_group)

        controls_row = QHBoxLayout()
        self.batch_start_button = QPushButton("Run Batch Job")
        controls_row.addWidget(self.batch_start_button)
        self.batch_cancel_button = QPushButton("Cancel")
        self.batch_cancel_button.setEnabled(False)
        controls_row.addWidget(self.batch_cancel_button)
        self.batch_open_button = QPushButton("Open Output")
        self.batch_open_button.setEnabled(False)
        controls_row.addWidget(self.batch_open_button)
        self.batch_save_button = QPushButton("Save Preset")
        controls_row.addWidget(self.batch_save_button)
        controls_row.addStretch(1)
        layout.addLayout(controls_row)

        status_row = QHBoxLayout()
        self.batch_status_label = QLabel("Status: idle")
        self.batch_progress_bar = QProgressBar()
        self.batch_progress_bar.setRange(0, 1)
        self.batch_progress_bar.setValue(0)
        status_row.addWidget(self.batch_status_label)
        status_row.addStretch(1)
        status_row.addWidget(self.batch_progress_bar)
        layout.addLayout(status_row)

        self.batch_log_output = QPlainTextEdit()
        self.batch_log_output.setReadOnly(True)
        self.batch_log_output.setPlaceholderText("Batch job logs will appear here.")
        self.batch_log_output.setMaximumBlockCount(500)
        layout.addWidget(self.batch_log_output, stretch=1)

        history_group = QGroupBox("Saved Presets & History")
        history_layout = QVBoxLayout(history_group)
        history_layout.setContentsMargins(8, 8, 8, 8)
        history_layout.setSpacing(6)

        self.batch_history_list = QListWidget()
        self.batch_history_list.setSelectionMode(QListWidget.SingleSelection)
        history_layout.addWidget(self.batch_history_list)

        history_buttons = QHBoxLayout()
        self.batch_history_load_button = QPushButton("Load")
        self.batch_history_run_button = QPushButton("Run Selected")
        self.batch_history_delete_button = QPushButton("Remove")
        history_buttons.addWidget(self.batch_history_load_button)
        history_buttons.addWidget(self.batch_history_run_button)
        history_buttons.addWidget(self.batch_history_delete_button)
        history_buttons.addStretch(1)
        history_layout.addLayout(history_buttons)

        layout.addWidget(history_group)

        outputs_group = QGroupBox("Recent Output Files")
        outputs_layout = QVBoxLayout(outputs_group)
        outputs_layout.setContentsMargins(8, 8, 8, 8)
        outputs_layout.setSpacing(6)

        self.batch_output_list = QListWidget()
        self.batch_output_list.setSelectionMode(QListWidget.SingleSelection)
        outputs_layout.addWidget(self.batch_output_list)

        self.batch_output_preview = QPlainTextEdit()
        self.batch_output_preview.setReadOnly(True)
        self.batch_output_preview.setPlaceholderText("Select an output file to preview the first rows.")
        self.batch_output_preview.setMaximumBlockCount(300)
        outputs_layout.addWidget(self.batch_output_preview)

        outputs_buttons = QHBoxLayout()
        self.batch_output_open_button = QPushButton("Open")
        self.batch_output_reveal_button = QPushButton("Reveal Folder")
        self.batch_output_load_button = QPushButton("Load Preset")
        self.batch_output_run_button = QPushButton("Run Preset")
        outputs_buttons.addWidget(self.batch_output_open_button)
        outputs_buttons.addWidget(self.batch_output_reveal_button)
        outputs_buttons.addWidget(self.batch_output_load_button)
        outputs_buttons.addWidget(self.batch_output_run_button)
        outputs_buttons.addStretch(1)
        outputs_layout.addLayout(outputs_buttons)

        layout.addWidget(outputs_group)

        return container

    # ------------------------------------------------------------------
    def _connect_signals(self) -> None:
        self.start_button.clicked.connect(self._on_start_clicked)
        self.stop_button.clicked.connect(self._on_stop_clicked)

        self._capture_bridge.flow_generated.connect(self._on_flow_generated)
        self._capture_bridge.status_changed.connect(self._on_status_changed)
        self._capture_bridge.error_occurred.connect(self._on_error)
        self._capture_bridge.running_changed.connect(self._on_running_changed)

        self.batch_input_file_button.clicked.connect(self._on_batch_browse_file)
        self.batch_input_dir_button.clicked.connect(self._on_batch_browse_dir)
        self.batch_output_button.clicked.connect(self._on_batch_browse_output)
        self.batch_start_button.clicked.connect(self._on_batch_start_clicked)
        self.batch_cancel_button.clicked.connect(self._on_batch_cancel_clicked)
        self.batch_open_button.clicked.connect(self._on_batch_open_output)
        self.batch_save_button.clicked.connect(self._on_batch_save_preset)
        self.batch_history_load_button.clicked.connect(self._on_batch_history_load)
        self.batch_history_run_button.clicked.connect(self._on_batch_history_run)
        self.batch_history_delete_button.clicked.connect(self._on_batch_history_delete)
        self.batch_history_list.itemDoubleClicked.connect(lambda _: self._on_batch_history_load())
        self.batch_history_list.currentRowChanged.connect(self._on_history_selection_changed)
        self.batch_output_open_button.clicked.connect(self._on_output_open)
        self.batch_output_reveal_button.clicked.connect(self._on_output_reveal)
        self.batch_output_load_button.clicked.connect(self._on_output_load_preset)
        self.batch_output_run_button.clicked.connect(self._on_output_run_preset)
        self.batch_output_list.itemDoubleClicked.connect(lambda _: self._on_output_open())
        self.batch_output_list.currentRowChanged.connect(self._on_output_selection_changed)

        self.batch_runner.job_started.connect(self._on_batch_job_started)
        self.batch_runner.job_progress.connect(self._on_batch_job_progress)
        self.batch_runner.job_log.connect(self._on_batch_job_log)
        self.batch_runner.job_finished.connect(self._on_batch_job_finished)
        self.batch_runner.job_failed.connect(self._on_batch_job_failed)
        self.batch_runner.job_cancelled.connect(self._on_batch_job_cancelled)
        self.batch_runner.job_outputs.connect(self._on_batch_job_outputs)

    def _populate_interfaces(self) -> None:
        interfaces = self._list_interfaces()
        if not interfaces:
            self.status_label.setText("Status: no interfaces detected")
            return
        self.interface_combo.addItems(interfaces)
        if "en0" in interfaces:  # Common default on macOS laptops
            self.interface_combo.setCurrentText("en0")

    # ------------------------------------------------------------------
    def _on_start_clicked(self) -> None:
        interface = self.interface_combo.currentText().strip()
        if not interface:
            QMessageBox.warning(self, "Interface Required", "Please choose a network interface.")
            return

        if not (self.ipv4_box.isChecked() or self.ipv6_box.isChecked()):
            QMessageBox.warning(self, "Protocol Selection", "Enable at least IPv4 or IPv6 parsing.")
            return

        options = CaptureOptions(
            interface=interface,
            bidirectional=self.bidirectional_box.isChecked(),
            flow_timeout_s=float(self.flow_timeout_spin.value()),
            activity_timeout_s=float(self.activity_timeout_spin.value()),
            read_ip4=self.ipv4_box.isChecked(),
            read_ip6=self.ipv6_box.isChecked(),
            bpf_filter=self.filter_line.text().strip() or None,
        )

        if self._capture_bridge.start(options):
            self._flow_model.clear()
            self.flow_rate_chart.reset()
            self.analytics_pane.reset()
            self._total_flows = 0
            self.flow_count_label.setText("Flows captured: 0")
            self.log_output.clear()
            self._set_controls_enabled(False)
            self._append_log(f"Capture started on {interface}")
        else:
            logger.debug("Failed to start capture via bridge")

    def _on_stop_clicked(self) -> None:
        self._capture_bridge.stop()
        self._append_log("Capture stop requested")

    def _on_flow_generated(self, summary: FlowSummary) -> None:
        self._flow_model.add_flow(summary)
        self._total_flows += 1
        self.flow_count_label.setText(f"Flows captured: {self._total_flows}")
        self.flow_rate_chart.record_flow(summary)
        self.analytics_pane.record_flow(summary)
        self._append_log(
            "Flow %s %s:%s -> %s:%s (%s packets)" % (
                summary.flow_id,
                summary.src_ip,
                summary.src_port,
                summary.dst_ip,
                summary.dst_port,
                summary.packets,
            )
        )

    def _on_status_changed(self, message: str) -> None:
        self.status_label.setText(f"Status: {message}")
        self._append_log(message)

    def _on_error(self, message: str) -> None:
        self.status_label.setText(f"Status: error")
        self._append_log(f"Error: {message}")
        QMessageBox.critical(self, "Live Capture", message)

    def _on_cluster_selected(self, flows: List[FlowSummary]) -> None:
        flow_ids = [flow.flow_id for flow in flows if flow.flow_id]
        self._highlight_flows_by_ids(flow_ids)
        if flows:
            self._append_log(f"Analytics cluster selected ({len(flows)} flows)")

    def _on_cluster_export(self, flows: List[FlowSummary]) -> None:
        if not flows:
            QMessageBox.information(self, "Export Cluster", "Select a populated cluster to export.")
            return
        default_name = "cluster_export.csv"
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Cluster Flows",
            str(Path.home() / default_name),
            "CSV Files (*.csv);;All Files (*)",
        )
        if not path:
            return

        header = [
            "flow_id",
            "timestamp",
            "src_ip",
            "src_port",
            "dst_ip",
            "dst_port",
            "protocol",
            "packets",
            "bytes",
            "duration_s",
        ]
        try:
            with open(path, "w", newline="", encoding="utf-8") as handle:
                writer = csv.writer(handle)
                writer.writerow(header)
                for flow in flows:
                    writer.writerow(
                        [
                            flow.flow_id,
                            flow.timestamp,
                            flow.src_ip,
                            flow.src_port,
                            flow.dst_ip,
                            flow.dst_port,
                            flow.protocol,
                            flow.packets,
                            flow.bytes,
                            f"{flow.duration_s:.6f}",
                        ]
                    )
        except OSError as exc:
            QMessageBox.critical(self, "Export Cluster", f"Failed to write CSV: {exc}")
            return

        QMessageBox.information(
            self,
            "Export Cluster",
            f"Exported {len(flows)} flows to {path}",
        )

    def _on_running_changed(self, running: bool) -> None:
        self.start_button.setEnabled(not running)
        self.stop_button.setEnabled(running)
        self._set_controls_enabled(not running)
        if not running:
            self.status_label.setText("Status: idle")

    # ------------------------------------------------------------------
    def _on_batch_browse_file(self) -> None:
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select PCAP file",
            "",
            "PCAP Files (*.pcap *.pcapng);;All Files (*)",
        )
        if file_path:
            self.batch_input_line.setText(file_path)

    def _on_batch_browse_dir(self) -> None:
        directory = QFileDialog.getExistingDirectory(self, "Select PCAP directory")
        if directory:
            self.batch_input_line.setText(directory)

    def _on_batch_browse_output(self) -> None:
        directory = QFileDialog.getExistingDirectory(self, "Select output directory")
        if directory:
            self.batch_output_line.setText(directory)

    def _on_batch_start_clicked(self) -> None:
        if self.batch_runner.is_running():
            QMessageBox.information(self, "Batch Job", "A batch job is already in progress.")
            return

        preset = self._collect_preset_from_inputs()
        if preset is None:
            return

        self._start_batch_with_preset(preset)

    def _on_batch_job_started(self, source: str, total_pcaps: int) -> None:
        self.batch_status_label.setText(f"Status: processing ({total_pcaps} capture(s))")
        self.batch_progress_bar.setRange(0, total_pcaps)
        self.batch_progress_bar.setValue(0)
        self._append_batch_log(f"Starting batch job from {source} ({total_pcaps} capture(s))")

    def _on_batch_job_progress(self, index: int, total: int, name: str) -> None:
        self.batch_progress_bar.setValue(index)
        self.batch_status_label.setText(f"Status: {index}/{total} - {name}")

    def _on_batch_job_log(self, message: str) -> None:
        self._append_batch_log(message)

    def _on_batch_job_finished(self, flows: int, packets: int, pcaps: int) -> None:
        self._append_batch_log(
            f"Batch complete: {pcaps} capture(s), {flows} flows, {packets} packets processed."
        )
        self.batch_status_label.setText("Status: completed")
        self.batch_progress_bar.setRange(0, 1)
        self.batch_progress_bar.setValue(1)
        self._set_batch_controls_enabled(True)
        self.batch_cancel_button.setEnabled(False)
        self.batch_open_button.setEnabled(self._last_batch_output is not None)
        self._active_batch_preset = None

    def _on_batch_job_failed(self, message: str) -> None:
        self._append_batch_log(f"Error: {message}")
        self.batch_status_label.setText("Status: failed")
        self.batch_progress_bar.setRange(0, 1)
        self.batch_progress_bar.setValue(0)
        self._set_batch_controls_enabled(True)
        self.batch_cancel_button.setEnabled(False)
        self.batch_open_button.setEnabled(False)
        QMessageBox.critical(self, "Batch Job", message)
        self._active_batch_preset = None

    def _on_batch_job_cancelled(self) -> None:
        self._append_batch_log("Batch job cancelled")
        self.batch_status_label.setText("Status: cancelled")
        self.batch_progress_bar.setRange(0, 1)
        self.batch_progress_bar.setValue(0)
        self._set_batch_controls_enabled(True)
        self.batch_cancel_button.setEnabled(False)
        self.batch_open_button.setEnabled(False)
        self._active_batch_preset = None

    def _on_batch_cancel_clicked(self) -> None:
        if self.batch_runner.cancel_job():
            self.batch_cancel_button.setEnabled(False)
            self._append_batch_log("Cancellation requested…")

    def _on_batch_open_output(self) -> None:
        if not self._last_batch_output:
            return
        url = QUrl.fromLocalFile(self._last_batch_output)
        QDesktopServices.openUrl(url)

    def _on_batch_save_preset(self) -> None:
        preset = self._collect_preset_from_inputs()
        if preset is None:
            return
        self._store_batch_preset(preset)
        QMessageBox.information(self, "Batch Preset", "Preset saved to history.")

    def _on_batch_history_load(self) -> None:
        preset = self._selected_history_preset()
        if preset is None:
            QMessageBox.information(self, "Batch Preset", "Select a preset to load.")
            return
        self._apply_preset_to_form(preset)

    def _on_batch_history_run(self) -> None:
        if self.batch_runner.is_running():
            QMessageBox.information(self, "Batch Job", "A batch job is already in progress.")
            return
        preset = self._selected_history_preset()
        if preset is None:
            QMessageBox.information(self, "Batch Preset", "Select a preset to run.")
            return
        refreshed = self._preset_with_current_timestamp(preset)
        self._start_batch_with_preset(refreshed)

    def _on_batch_history_delete(self) -> None:
        preset = self._selected_history_preset()
        if preset is None:
            return
        key = self._preset_key(preset)
        self._batch_history = [item for item in self._batch_history if self._preset_key(item) != key]
        save_history(self._batch_history)
        self._refresh_history_list()

    def _on_history_selection_changed(self, _index: int) -> None:
        self._update_history_button_states()

    # ------------------------------------------------------------------
    def _collect_preset_from_inputs(self) -> Optional[BatchPreset]:
        source = self.batch_input_line.text().strip()
        output_dir = self.batch_output_line.text().strip()

        if not source:
            QMessageBox.warning(self, "Batch Job", "Provide a PCAP file or directory to process.")
            return None

        if not output_dir:
            QMessageBox.warning(self, "Batch Job", "Select an output directory for CSV results.")
            return None

        if not (self.batch_ipv4_box.isChecked() or self.batch_ipv6_box.isChecked()):
            QMessageBox.warning(self, "Batch Job", "Enable at least IPv4 or IPv6 parsing.")
            return None

        created_at = datetime.utcnow().isoformat(timespec="seconds")
        return BatchPreset(
            source=source,
            output_dir=output_dir,
            bidirectional=self.batch_bidirectional_box.isChecked(),
            flow_timeout_s=float(self.batch_flow_timeout_spin.value()),
            activity_timeout_s=float(self.batch_activity_timeout_spin.value()),
            read_ip4=self.batch_ipv4_box.isChecked(),
            read_ip6=self.batch_ipv6_box.isChecked(),
            created_at=created_at,
        )

    def _start_batch_with_preset(self, preset: BatchPreset) -> None:
        options = BatchOptions(
            bidirectional=preset.bidirectional,
            flow_timeout_s=preset.flow_timeout_s,
            activity_timeout_s=preset.activity_timeout_s,
            read_ip4=preset.read_ip4,
            read_ip6=preset.read_ip6,
        )

        started = self.batch_runner.start_job(preset.source, preset.output_dir, options)
        if not started:
            QMessageBox.information(self, "Batch Job", "A batch job is already running.")
            return

        self._store_batch_preset(preset)
        self._prepare_batch_run_ui(preset)

    def _prepare_batch_run_ui(self, preset: BatchPreset) -> None:
        self._active_batch_preset = preset
        self._last_batch_output = preset.output_dir
        self._set_batch_controls_enabled(False)
        self.batch_status_label.setText("Status: starting…")
        self.batch_log_output.clear()
        self.batch_progress_bar.setRange(0, 0)
        self.batch_progress_bar.setValue(0)
        self.batch_cancel_button.setEnabled(True)
        self.batch_open_button.setEnabled(False)
        self._update_history_button_states()

    def _apply_preset_to_form(self, preset: BatchPreset) -> None:
        self.batch_input_line.setText(preset.source)
        self.batch_output_line.setText(preset.output_dir)
        self.batch_bidirectional_box.setChecked(preset.bidirectional)
        self.batch_flow_timeout_spin.setValue(preset.flow_timeout_s)
        self.batch_activity_timeout_spin.setValue(preset.activity_timeout_s)
        self.batch_ipv4_box.setChecked(preset.read_ip4)
        self.batch_ipv6_box.setChecked(preset.read_ip6)

    def _store_batch_preset(self, preset: BatchPreset) -> None:
        self._batch_history = add_entry(self._batch_history, preset)
        save_history(self._batch_history)
        self._refresh_history_list()

    def _refresh_history_list(self) -> None:
        selected_key = self._current_history_key()
        self.batch_history_list.blockSignals(True)
        self.batch_history_list.clear()
        for preset in self._batch_history:
            item = QListWidgetItem(preset.display_label())
            item.setData(Qt.UserRole, preset)
            self.batch_history_list.addItem(item)
        self.batch_history_list.blockSignals(False)

        if self.batch_history_list.count() > 0:
            target_index = 0
            if selected_key is not None:
                for index in range(self.batch_history_list.count()):
                    item = self.batch_history_list.item(index)
                    preset = item.data(Qt.UserRole)
                    if isinstance(preset, BatchPreset) and self._preset_key(preset) == selected_key:
                        target_index = index
                        break
            self.batch_history_list.setCurrentRow(target_index)
        self._update_history_button_states()

    def _selected_history_preset(self) -> Optional[BatchPreset]:
        item = self.batch_history_list.currentItem()
        if item is None:
            return None
        preset = item.data(Qt.UserRole)
        if isinstance(preset, BatchPreset):
            return preset
        return None

    def _current_history_key(self) -> Optional[tuple]:
        preset = self._selected_history_preset()
        if preset is None:
            return None
        return self._preset_key(preset)

    @staticmethod
    def _preset_key(preset: BatchPreset) -> tuple:
        return (
            preset.source,
            preset.output_dir,
            preset.bidirectional,
            round(preset.flow_timeout_s, 3),
            round(preset.activity_timeout_s, 3),
            preset.read_ip4,
            preset.read_ip6,
        )

    def _preset_with_current_timestamp(self, preset: BatchPreset) -> BatchPreset:
        return BatchPreset(
            source=preset.source,
            output_dir=preset.output_dir,
            bidirectional=preset.bidirectional,
            flow_timeout_s=preset.flow_timeout_s,
            activity_timeout_s=preset.activity_timeout_s,
            read_ip4=preset.read_ip4,
            read_ip6=preset.read_ip6,
            created_at=datetime.utcnow().isoformat(timespec="seconds"),
        )

    def _update_history_button_states(self) -> None:
        has_selection = self.batch_history_list.currentItem() is not None
        allow_actions = not self.batch_runner.is_running()
        self.batch_history_load_button.setEnabled(has_selection and allow_actions)
        self.batch_history_run_button.setEnabled(has_selection and allow_actions)
        self.batch_history_delete_button.setEnabled(has_selection and allow_actions)

    # ------------------------------------------------------------------
    def _on_batch_job_outputs(self, paths: List[str]) -> None:
        timestamp = datetime.utcnow().isoformat(timespec="seconds")
        preset_dict = (
            self._active_batch_preset.to_dict() if self._active_batch_preset else None
        )
        self._recent_outputs = add_outputs(
            self._recent_outputs,
            paths,
            timestamp=timestamp,
            preset=preset_dict,
        )
        save_outputs(self._recent_outputs)
        self._refresh_output_list()

    def _refresh_output_list(self) -> None:
        selected_path = self._current_output_path()
        self.batch_output_list.blockSignals(True)
        self.batch_output_list.clear()
        for record in self._recent_outputs:
            item = QListWidgetItem(record.display_label())
            item.setData(Qt.UserRole, record)
            self.batch_output_list.addItem(item)
        self.batch_output_list.blockSignals(False)

        if self.batch_output_list.count() > 0:
            target = 0
            if selected_path:
                for index in range(self.batch_output_list.count()):
                    item = self.batch_output_list.item(index)
                    record = item.data(Qt.UserRole)
                    if isinstance(record, BatchOutputRecord) and record.path == selected_path:
                        target = index
                        break
            self.batch_output_list.setCurrentRow(target)
        self._load_output_preview()
        self._update_output_button_states()

    def _selected_output_record(self) -> Optional[BatchOutputRecord]:
        item = self.batch_output_list.currentItem()
        if item is None:
            return None
        record = item.data(Qt.UserRole)
        if isinstance(record, BatchOutputRecord):
            return record
        return None

    def _current_output_path(self) -> Optional[str]:
        record = self._selected_output_record()
        return record.path if record is not None else None

    def _on_output_open(self) -> None:
        record = self._selected_output_record()
        if record is None:
            return
        path = Path(record.path)
        if not path.exists():
            QMessageBox.warning(self, "Open Output", f"File not found: {record.path}")
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    def _on_output_reveal(self) -> None:
        record = self._selected_output_record()
        if record is None:
            return
        path = Path(record.path)
        directory = path.parent if path.exists() else path.parent
        if not directory.exists():
            QMessageBox.warning(self, "Reveal Output", f"Folder not found: {directory}")
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(directory)))

    def _on_output_selection_changed(self, _index: int) -> None:
        self._load_output_preview()
        self._update_output_button_states()

    def _update_output_button_states(self) -> None:
        record = self._selected_output_record()
        if record is None:
            self.batch_output_open_button.setEnabled(False)
            self.batch_output_reveal_button.setEnabled(False)
            self.batch_output_load_button.setEnabled(False)
            self.batch_output_run_button.setEnabled(False)
            return

        path = Path(record.path)
        parent_exists = path.parent.exists()
        self.batch_output_open_button.setEnabled(path.exists())
        self.batch_output_reveal_button.setEnabled(parent_exists)

        allow_preset_actions = bool(record.preset) and not self.batch_runner.is_running()
        self.batch_output_load_button.setEnabled(allow_preset_actions)
        self.batch_output_run_button.setEnabled(allow_preset_actions)

    def _load_output_preview(self) -> None:
        record = self._selected_output_record()
        if record is None:
            self.batch_output_preview.clear()
            return
        path = Path(record.path)
        if not path.exists():
            self.batch_output_preview.setPlainText("File not found.")
            return
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as handle:
                lines = []
                for _ in range(25):
                    line = handle.readline()
                    if not line:
                        break
                    lines.append(line.rstrip("\n"))
            header = f"# {path}"
            preview_body = "\n".join(lines)
            preview = header if not preview_body else f"{header}\n{preview_body}"
            if not preview:
                preview = "(File is empty)"
            self.batch_output_preview.setPlainText(preview)
        except Exception as exc:
            self.batch_output_preview.setPlainText(f"Failed to read preview: {exc}")

    def _on_output_load_preset(self) -> None:
        record = self._selected_output_record()
        if record is None or not record.preset:
            return
        try:
            preset = BatchPreset.from_dict(record.preset)
        except Exception:
            QMessageBox.warning(self, "Load Preset", "Saved preset data is invalid.")
            return
        refreshed = self._preset_with_current_timestamp(preset)
        self._apply_preset_to_form(refreshed)
        self._store_batch_preset(refreshed)
        QMessageBox.information(self, "Load Preset", "Preset applied from output metadata.")

    def _on_output_run_preset(self) -> None:
        record = self._selected_output_record()
        if record is None or not record.preset:
            return
        if self.batch_runner.is_running():
            QMessageBox.information(self, "Batch Job", "A batch job is already in progress.")
            return
        try:
            preset = BatchPreset.from_dict(record.preset)
        except Exception:
            QMessageBox.warning(self, "Run Preset", "Saved preset data is invalid.")
            return
        refreshed = self._preset_with_current_timestamp(preset)
        self._start_batch_with_preset(refreshed)

    def _highlight_flows_by_ids(self, flow_ids: List[str]) -> None:
        selection_model = self.flow_table.selectionModel()
        if selection_model is None:
            return
        selection_model.clearSelection()
        indices = self._flow_model.find_rows_by_ids(flow_ids)
        if not indices:
            return
        for row in indices:
            index = self._flow_model.index(row, 0)
            selection_model.select(
                index,
                QItemSelectionModel.Select | QItemSelectionModel.Rows,
            )
        self.flow_table.scrollTo(self._flow_model.index(indices[0], 0))


    # ------------------------------------------------------------------
    def _set_controls_enabled(self, enabled: bool) -> None:
        self.interface_combo.setEnabled(enabled)
        self.filter_line.setEnabled(enabled)
        self.bidirectional_box.setEnabled(enabled)
        self.ipv4_box.setEnabled(enabled)
        self.ipv6_box.setEnabled(enabled)
        self.flow_timeout_spin.setEnabled(enabled)
        self.activity_timeout_spin.setEnabled(enabled)

    def _append_log(self, message: str) -> None:
        self.log_output.appendPlainText(message)
        cursor = self.log_output.textCursor()
        cursor.movePosition(cursor.End)
        self.log_output.setTextCursor(cursor)

    def _set_batch_controls_enabled(self, enabled: bool) -> None:
        widgets = [
            self.batch_input_line,
            self.batch_input_file_button,
            self.batch_input_dir_button,
            self.batch_output_line,
            self.batch_output_button,
            self.batch_bidirectional_box,
            self.batch_ipv4_box,
            self.batch_ipv6_box,
            self.batch_flow_timeout_spin,
            self.batch_activity_timeout_spin,
            self.batch_save_button,
        ]
        for widget in widgets:
            widget.setEnabled(enabled)
        self.batch_start_button.setEnabled(enabled)
        self._update_history_button_states()
        self._update_output_button_states()

    def _append_batch_log(self, message: str) -> None:
        self.batch_log_output.appendPlainText(message)
        cursor = self.batch_log_output.textCursor()
        cursor.movePosition(cursor.End)
        self.batch_log_output.setTextCursor(cursor)

    @staticmethod
    def _list_interfaces() -> List[str]:
        try:
            entries = socket.if_nameindex()
        except OSError as exc:
            logger.warning("Unable to enumerate interfaces: %s", exc)
            return []

        seen = set()
        result: List[str] = []
        for _, name in entries:
            if name not in seen:
                seen.add(name)
                result.append(name)
        result.sort()
        return result

    # ------------------------------------------------------------------
    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802 - Qt API
        if self._capture_bridge.is_running():
            self._capture_bridge.stop()
        super().closeEvent(event)


__all__ = ["MainWindow"]
