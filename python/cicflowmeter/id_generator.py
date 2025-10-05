"""Straightforward port of the Java IdGenerator."""

from __future__ import annotations

from threading import Lock


class IdGenerator:
    """Thread-safe monotonically increasing identifier generator."""

    __slots__ = ("_lock", "_next")

    def __init__(self, initial: int = 0) -> None:
        self._lock = Lock()
        self._next = int(initial)

    def next_id(self) -> int:
        with self._lock:
            self._next += 1
            return self._next


__all__ = ["IdGenerator"]
