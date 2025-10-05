"""Utility helpers used by the flow parser translation."""

from __future__ import annotations

import ipaddress
import os
from typing import Union

FILE_SEP = os.sep
LINE_SEP = os.linesep
FLOW_SUFFIX = "_Flow.csv"


def format_ip(value: Union[bytes, bytearray, str]) -> str:
    """Convert a raw IP buffer into a printable string."""
    if isinstance(value, (bytes, bytearray)):
        if len(value) == 4:
            return ".".join(str(b & 0xFF) for b in value)
        if len(value) == 16:
            return str(ipaddress.IPv6Address(value))
    return str(value)


__all__ = ["FILE_SEP", "LINE_SEP", "FLOW_SUFFIX", "format_ip"]
