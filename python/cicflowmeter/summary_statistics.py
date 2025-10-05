"""Light-weight reimplementation of Apache Commons SummaryStatistics."""

from __future__ import annotations

from math import sqrt
from typing import Optional


class SummaryStatistics:
    """Incremental aggregator mirroring the Java SummaryStatistics API."""

    __slots__ = ("_count", "_sum", "_sum_sq", "_min", "_max")

    def __init__(self) -> None:
        self._count: int = 0
        self._sum: float = 0.0
        self._sum_sq: float = 0.0
        self._min: Optional[float] = None
        self._max: Optional[float] = None

    def add_value(self, value: float) -> None:
        self._count += 1
        self._sum += value
        self._sum_sq += value * value
        self._min = value if self._min is None else min(self._min, value)
        self._max = value if self._max is None else max(self._max, value)

    # Apache-style getters -------------------------------------------------

    def getN(self) -> int:
        return self._count

    def getSum(self) -> float:
        return self._sum

    def getMean(self) -> float:
        if self._count == 0:
            return 0.0
        return self._sum / self._count

    def getVariance(self) -> float:
        if self._count < 2:
            return 0.0
        mean_sq = (self._sum * self._sum) / self._count
        return (self._sum_sq - mean_sq) / (self._count - 1)

    def getStandardDeviation(self) -> float:
        return sqrt(self.getVariance())

    def getMax(self) -> float:
        return 0.0 if self._max is None else self._max

    def getMin(self) -> float:
        return 0.0 if self._min is None else self._min


__all__ = ["SummaryStatistics"]
