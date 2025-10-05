"""Ancillary reporting utilities ported from the Java toolchain."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, MutableMapping, Optional, Sequence, Union

from .basic_flow import BasicFlow
from .utils import LINE_SEP


@dataclass
class EndpointSummary:
    """Aggregate view of flows touching a particular IP endpoint."""

    flows_as_src: int = 0
    flows_as_dst: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    bytes_sent: float = 0.0
    bytes_received: float = 0.0

    @property
    def total_flows(self) -> int:
        return self.flows_as_src + self.flows_as_dst

    @property
    def total_packets(self) -> int:
        return self.packets_sent + self.packets_received

    @property
    def total_bytes(self) -> float:
        return self.bytes_sent + self.bytes_received


@dataclass
class TimeBucket:
    """Roll-up of flow activity inside a fixed time window."""

    start_us: int
    end_us: int
    flow_count: int = 0
    packet_count: int = 0
    byte_count: float = 0.0

    @property
    def start_seconds(self) -> float:
        return self.start_us / 1_000_000

    @property
    def end_seconds(self) -> float:
        return self.end_us / 1_000_000


class IncrementalCSVWriter:
    """Utility mirroring the Java InsertCsvRow helper."""

    def __init__(self, file_path: Union[str, Path], header: Optional[str] = None) -> None:
        self.file_path = Path(file_path)
        self.header = header
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        self._header_written = (
            self.file_path.exists() and self.file_path.stat().st_size > 0
        )

    def append_rows(self, rows: Iterable[str]) -> int:
        row_list = [row for row in rows if row]
        if not row_list:
            return 0

        with self.file_path.open("a", encoding="utf-8") as handle:
            if not self._header_written and self.header is not None:
                handle.write(self.header + LINE_SEP)
                self._header_written = True
            for row in row_list:
                handle.write(row + LINE_SEP)

        return len(row_list)

    @classmethod
    def insert(
        cls,
        header: Optional[str],
        rows: Union[str, Sequence[str]],
        savepath: Union[str, Path],
        filename: Union[str, Path],
    ) -> int:
        if not savepath or not filename:
            raise ValueError("savepath and filename must be provided")

        if isinstance(rows, str):
            row_list: List[str] = [rows]
        else:
            row_list = [row for row in rows if row]

        if not row_list:
            return 0

        target_path = Path(savepath) / Path(filename)
        writer = cls(target_path, header)
        return writer.append_rows(row_list)


def summarize_ip_endpoints(flows: Iterable[BasicFlow]) -> Dict[str, EndpointSummary]:
    """Generate src/dst packet and byte counts per IP address."""

    summary: MutableMapping[str, EndpointSummary] = {}

    for flow in flows:
        src_ip = flow.get_src_ip()
        dst_ip = flow.get_dst_ip()

        src_entry = summary.setdefault(src_ip, EndpointSummary())
        src_entry.flows_as_src += 1
        src_entry.packets_sent += flow.get_total_fwd_packets()
        src_entry.bytes_sent += flow.get_total_length_of_fwd_packets()
        src_entry.packets_received += flow.get_total_backward_packets()
        src_entry.bytes_received += flow.get_total_length_of_bwd_packets()

        dst_entry = summary.setdefault(dst_ip, EndpointSummary())
        dst_entry.flows_as_dst += 1
        dst_entry.packets_received += flow.get_total_fwd_packets()
        dst_entry.bytes_received += flow.get_total_length_of_fwd_packets()
        dst_entry.packets_sent += flow.get_total_backward_packets()
        dst_entry.bytes_sent += flow.get_total_length_of_bwd_packets()

    return dict(summary)


def aggregate_flows_by_interval(
    flows: Iterable[BasicFlow],
    interval_seconds: float,
) -> List[TimeBucket]:
    """Bucket flows by start timestamp using the provided interval."""

    if interval_seconds <= 0:
        raise ValueError("interval_seconds must be positive")

    interval_us = int(interval_seconds * 1_000_000)
    buckets: MutableMapping[int, TimeBucket] = {}

    for flow in flows:
        start_us = flow.get_flow_start_time()
        bucket_start = (start_us // interval_us) * interval_us
        bucket = buckets.get(bucket_start)
        if bucket is None:
            bucket = TimeBucket(start_us=bucket_start, end_us=bucket_start + interval_us)
            buckets[bucket_start] = bucket

        bucket.flow_count += 1
        bucket.packet_count += flow.packet_count()
        bucket.byte_count += (
            flow.get_total_length_of_fwd_packets() + flow.get_total_length_of_bwd_packets()
        )

    return [buckets[key] for key in sorted(buckets)]


__all__ = [
    "EndpointSummary",
    "TimeBucket",
    "IncrementalCSVWriter",
    "summarize_ip_endpoints",
    "aggregate_flows_by_interval",
]
