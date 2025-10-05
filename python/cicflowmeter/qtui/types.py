"""Shared dataclasses for the Qt operator UI."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class FlowSummary:
    """Compact representation of a finished flow for table display."""

    flow_id: str
    timestamp: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    packets: int
    bytes: int
    duration_s: float
    start_micros: int


__all__ = ["FlowSummary"]
