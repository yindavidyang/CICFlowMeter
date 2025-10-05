"""Utility formatting helpers for micro/milli second timestamps."""

from __future__ import annotations

from datetime import datetime
from typing import Optional


_DEFAULT_FORMAT = "%d/%m/%Y %I:%M:%S"


def parse_date_from_long(time_millis: int, fmt: Optional[str] = None) -> str:
    """Mirror of the Java helper that renders epoch milliseconds."""
    pattern = fmt or _DEFAULT_FORMAT
    dt = datetime.fromtimestamp(time_millis / 1000.0)
    return dt.strftime(pattern)


def convert_milliseconds_to_string(time_millis: int, fmt: Optional[str] = None) -> str:
    pattern = fmt or _DEFAULT_FORMAT
    dt = datetime.fromtimestamp(time_millis / 1000.0)
    return dt.strftime(pattern)


__all__ = ["parse_date_from_long", "convert_milliseconds_to_string"]
