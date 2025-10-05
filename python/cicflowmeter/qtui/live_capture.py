"""Qt-aware bridge around the live capture subsystem."""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import Optional

from PySide6.QtCore import QObject, Signal

from ..basic_flow import BasicFlow
from ..live_capture import LiveCapture, LiveCaptureError
from .types import FlowSummary

logger = logging.getLogger(__name__)

_MICROS_PER_SECOND = 1_000_000


@dataclass
class CaptureOptions:
    interface: str
    bidirectional: bool
    flow_timeout_s: float
    activity_timeout_s: float
    read_ip4: bool
    read_ip6: bool
    bpf_filter: Optional[str]


class QtLiveCaptureBridge(QObject):
    """Runs the live capture engine and re-emits events as Qt signals."""

    flow_generated = Signal(object)
    status_changed = Signal(str)
    error_occurred = Signal(str)
    running_changed = Signal(bool)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._capture: Optional[LiveCapture] = None
        self._lock = threading.RLock()
        self._running = False
        self._options: Optional[CaptureOptions] = None

    # ------------------------------------------------------------------
    def start(self, options: CaptureOptions) -> bool:
        """Start live capture with the provided options."""
        with self._lock:
            if self._running:
                self._emit_error("Capture already running")
                return False

            capture = LiveCapture(
                interface=options.interface,
                bidirectional=options.bidirectional,
                flow_timeout=int(options.flow_timeout_s * _MICROS_PER_SECOND),
                activity_timeout=int(options.activity_timeout_s * _MICROS_PER_SECOND),
                read_ip4=options.read_ip4,
                read_ip6=options.read_ip6,
                bpf_filter=options.bpf_filter or None,
                flow_listener=self,
                status_handler=self._handle_status_update,
            )

            try:
                capture.start()
            except LiveCaptureError as exc:
                self._emit_error(str(exc))
                return False
            except Exception as exc:  # pragma: no cover - defensive guard for runtime errors
                logger.exception("Unexpected error starting capture")
                self._emit_error(f"Failed to start capture: {exc}")
                return False

            self._capture = capture
            self._options = options
            self._running = True

        logger.info("Live capture started on %s", options.interface)
        self.running_changed.emit(True)
        return True

    def stop(self) -> None:
        """Stop the live capture if it is running."""
        with self._lock:
            capture = self._capture
            self._capture = None
            self._running = False

        if capture is None:
            return

        try:
            capture.stop()
        except Exception as exc:  # pragma: no cover - stop failures depend on runtime environment
            logger.exception("Error stopping live capture")
            self._emit_error(f"Error stopping capture: {exc}")

        self.running_changed.emit(False)
        logger.info("Live capture stopped")

    def is_running(self) -> bool:
        with self._lock:
            return self._running

    # ------------------------------------------------------------------
    def on_flow_generated(self, flow: BasicFlow) -> None:  # type: ignore[override]
        """Convert captured flows into lightweight summaries for the UI."""
        summary = self._build_summary(flow)
        if summary is None:
            return
        self.flow_generated.emit(summary)

    def _handle_status_update(self, message: str) -> None:
        self.status_changed.emit(message)

    def _emit_error(self, message: str) -> None:
        logger.error(message)
        self.error_occurred.emit(message)

    # ------------------------------------------------------------------
    @staticmethod
    def _build_summary(flow: BasicFlow) -> Optional[FlowSummary]:
        flow_id = flow.get_flow_id() or ""
        try:
            total_bytes = int(
                flow.get_total_length_of_fwd_packets() + flow.get_total_length_of_bwd_packets()
            )
        except Exception:  # pragma: no cover - defensive guard for unexpected states
            total_bytes = 0

        duration = max(flow.get_flow_duration(), 0) / _MICROS_PER_SECOND

        return FlowSummary(
            flow_id=flow_id,
            timestamp=flow.get_timestamp(),
            src_ip=flow.get_src_ip(),
            src_port=flow.get_src_port(),
            dst_ip=flow.get_dst_ip(),
            dst_port=flow.get_dst_port(),
            protocol=flow.get_protocol_str(),
            packets=flow.packet_count(),
            bytes=total_bytes,
            duration_s=duration,
            start_micros=flow.get_flow_start_time(),
        )


__all__ = ["CaptureOptions", "QtLiveCaptureBridge"]
