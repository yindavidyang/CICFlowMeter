"""Listener interfaces for flow generation events."""

from __future__ import annotations

from typing import Protocol

from .basic_flow import BasicFlow


class FlowGenListener(Protocol):
    def on_flow_generated(self, flow: BasicFlow) -> None:  # pragma: no cover - protocol definition
        ...


__all__ = ["FlowGenListener"]
