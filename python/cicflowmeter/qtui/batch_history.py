"""Persistence helpers for batch job presets and history."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import List

_HISTORY_PATH = Path.home() / ".cicflowmeter_gui_history.json"
_MAX_HISTORY = 12


@dataclass
class BatchPreset:
    source: str
    output_dir: str
    bidirectional: bool
    flow_timeout_s: float
    activity_timeout_s: float
    read_ip4: bool
    read_ip6: bool
    created_at: str

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "BatchPreset":
        return cls(
            source=data.get("source", ""),
            output_dir=data.get("output_dir", ""),
            bidirectional=bool(data.get("bidirectional", True)),
            flow_timeout_s=float(data.get("flow_timeout_s", 120.0)),
            activity_timeout_s=float(data.get("activity_timeout_s", 5.0)),
            read_ip4=bool(data.get("read_ip4", True)),
            read_ip6=bool(data.get("read_ip6", False)),
            created_at=data.get("created_at", datetime.utcnow().isoformat()),
        )

    def display_label(self) -> str:
        timestamp = self.created_at.replace("T", " ")
        mode = "bi" if self.bidirectional else "uni"
        protocols = []
        if self.read_ip4:
            protocols.append("IPv4")
        if self.read_ip6:
            protocols.append("IPv6")
        proto_label = "/".join(protocols) if protocols else "none"
        return f"{timestamp} • {self.source} → {self.output_dir} ({mode}, {proto_label})"


# ---------------------------------------------------------------------------
def load_history() -> List[BatchPreset]:
    if not _HISTORY_PATH.exists():
        return []
    try:
        raw = json.loads(_HISTORY_PATH.read_text(encoding="utf-8"))
    except Exception:
        return []
    presets = []
    for item in raw:
        try:
            presets.append(BatchPreset.from_dict(item))
        except Exception:
            continue
    return presets


def save_history(history: List[BatchPreset]) -> None:
    try:
        payload = [preset.to_dict() for preset in history[:_MAX_HISTORY]]
        _HISTORY_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except Exception:
        # Persistence should not crash the UI; errors can be ignored silently.
        pass


def add_entry(history: List[BatchPreset], preset: BatchPreset) -> List[BatchPreset]:
    deduped = [
        existing
        for existing in history
        if not (
            existing.source == preset.source
            and existing.output_dir == preset.output_dir
            and existing.bidirectional == preset.bidirectional
            and existing.read_ip4 == preset.read_ip4
            and existing.read_ip6 == preset.read_ip6
            and abs(existing.flow_timeout_s - preset.flow_timeout_s) < 1e-6
            and abs(existing.activity_timeout_s - preset.activity_timeout_s) < 1e-6
        )
    ]
    deduped.insert(0, preset)
    return deduped[:_MAX_HISTORY]


__all__ = ["BatchPreset", "load_history", "save_history", "add_entry"]
