"""Background batch processing for the Qt operator console."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from PySide6.QtCore import QObject, Signal

from ..cli import collect_pcaps, process_pcap
from ..utils import FLOW_SUFFIX


@dataclass
class BatchOptions:
    bidirectional: bool
    flow_timeout_s: float
    activity_timeout_s: float
    read_ip4: bool
    read_ip6: bool


class BatchJobRunner(QObject):
    """Runs PCAP batch jobs on a worker thread and reports progress via signals."""

    job_started = Signal(str, int)
    job_progress = Signal(int, int, str)
    job_log = Signal(str)
    job_finished = Signal(int, int, int)
    job_failed = Signal(str)
    job_cancelled = Signal()
    job_outputs = Signal(list)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.RLock()
        self._running = False
        self._cancel_event = threading.Event()

    # ------------------------------------------------------------------
    def start_job(self, pcap_path: str, output_dir: str, options: BatchOptions) -> bool:
        with self._lock:
            if self._running:
                return False
            self._running = True
            self._cancel_event.clear()

        self._thread = threading.Thread(
            target=self._run_job,
            args=(pcap_path, output_dir, options),
            daemon=True,
        )
        self._thread.start()
        return True

    def is_running(self) -> bool:
        with self._lock:
            return self._running

    def cancel_job(self) -> bool:
        with self._lock:
            if not self._running:
                return False
            self._cancel_event.set()
        return True

    # ------------------------------------------------------------------
    def _run_job(self, pcap_path: str, output_dir: str, options: BatchOptions) -> None:
        try:
            input_path = Path(pcap_path).expanduser().resolve()
            output_path = Path(output_dir).expanduser().resolve()

            if not input_path.exists():
                raise FileNotFoundError(f"PCAP path does not exist: {input_path}")

            try:
                pcaps = collect_pcaps(input_path)
            except Exception as exc:
                raise RuntimeError(str(exc)) from exc

            if not pcaps:
                raise RuntimeError("No PCAP files found for batch processing.")

            total_pcaps = len(pcaps)
            self.job_started.emit(str(input_path), total_pcaps)
            self.job_log.emit(f"Writing output to {output_path}")

            total_flows = 0
            total_packets = 0
            produced_files: List[str] = []

            for index, pcap in enumerate(pcaps, 1):
                if self._cancel_event.is_set():
                    self.job_log.emit("Cancellation requested; stopping batch job.")
                    self.job_cancelled.emit()
                    return
                self.job_progress.emit(index, total_pcaps, pcap.name)
                self.job_log.emit(f"Processing {pcap}")

                stats = process_pcap(
                    pcap,
                    output_path,
                    bidirectional=options.bidirectional,
                    flow_timeout_s=options.flow_timeout_s,
                    activity_timeout_s=options.activity_timeout_s,
                    read_ip4=options.read_ip4,
                    read_ip6=options.read_ip6,
                )

                total_flows += stats.flows_written
                total_packets += stats.valid_packets
                produced_files.append(str(output_path / f"{pcap.name}{FLOW_SUFFIX}"))

            self.job_outputs.emit(produced_files)
            self.job_finished.emit(total_flows, total_packets, total_pcaps)
        except Exception as exc:  # pragma: no cover - protects against runtime errors
            self.job_failed.emit(str(exc))
        finally:
            with self._lock:
                self._running = False


__all__ = ["BatchJobRunner", "BatchOptions"]
