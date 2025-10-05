"""Persistence helpers for recent batch output artifacts."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

_OUTPUT_PATH = Path.home() / ".cicflowmeter_gui_outputs.json"
_MAX_OUTPUTS = 20


@dataclass
class BatchOutputRecord:
    path: str
    created_at: str
    preset: Optional[Dict] = None

    def to_dict(self) -> dict:
        payload = asdict(self)
        return payload

    @classmethod
    def from_dict(cls, data: dict) -> "BatchOutputRecord":
        preset = data.get("preset") if isinstance(data.get("preset"), dict) else None
        return cls(
            path=data.get("path", ""),
            created_at=data.get("created_at", datetime.utcnow().isoformat()),
            preset=preset,
        )

    def display_label(self) -> str:
        timestamp = self.created_at.replace("T", " ")
        return f"{timestamp} • {Path(self.path).name}"


# ---------------------------------------------------------------------------
def load_outputs() -> List[BatchOutputRecord]:
    if not _OUTPUT_PATH.exists():
        return []
    try:
        raw = json.loads(_OUTPUT_PATH.read_text(encoding="utf-8"))
    except Exception:
        return []
    outputs: List[BatchOutputRecord] = []
    for item in raw:
        try:
            record = BatchOutputRecord.from_dict(item)
        except Exception:
            continue
        if record.path:
            outputs.append(record)
    return outputs


def save_outputs(outputs: List[BatchOutputRecord]) -> None:
    try:
        payload = [record.to_dict() for record in outputs[:_MAX_OUTPUTS]]
        _OUTPUT_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except Exception:
        pass


def add_outputs(
    outputs: List[BatchOutputRecord],
    paths: List[str],
    *,
    timestamp: str,
    preset: Optional[Dict] = None,
) -> List[BatchOutputRecord]:
    existing = {record.path: record for record in outputs}
    for path in paths:
        if not path:
            continue
        existing[path] = BatchOutputRecord(path=path, created_at=timestamp, preset=preset)
    ordered = sorted(existing.values(), key=lambda record: record.created_at, reverse=True)
    return ordered[:_MAX_OUTPUTS]


__all__ = ["BatchOutputRecord", "load_outputs", "save_outputs", "add_outputs"]
