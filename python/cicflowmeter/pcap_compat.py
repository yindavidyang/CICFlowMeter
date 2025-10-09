"""Compatibility helpers mirroring the subset of jNetPcap facilities used in Java."""

from __future__ import annotations

import logging
import socket
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence

from .live_capture import LiveCapture
from .packet_reader import PacketReader

logger = logging.getLogger(__name__)

try:  # pragma: no cover - optional dependency discovered at runtime
    import psutil  # type: ignore
except Exception:  # pragma: no cover - any import failure disables psutil usage
    psutil = None  # type: ignore


@dataclass(frozen=True)
class InterfaceAddress:
    """Network layer addressing for a capture device."""

    address: str
    netmask: Optional[str] = None
    broadcast: Optional[str] = None
    family: int = socket.AF_INET


@dataclass(frozen=True)
class PcapDevice:
    """Metadata describing a capture-capable network interface."""

    name: str
    description: Optional[str]
    addresses: Sequence[InterfaceAddress]
    hardware_address: Optional[str] = None
    is_loopback: bool = False


def list_devices(*, include_loopback: bool = True) -> List[PcapDevice]:
    """Return interfaces roughly equivalent to Pcap.findAllDevs()."""

    devices: List[PcapDevice] = []
    seen: set[str] = set()

    def _append_device(
        name: str,
        addresses: Iterable[InterfaceAddress],
        hardware: Optional[str],
        is_loop: bool,
    ) -> None:
        if not include_loopback and is_loop:
            return
        devices.append(
            PcapDevice(
                name=name,
                description=None,
                addresses=tuple(addresses),
                hardware_address=hardware,
                is_loopback=is_loop,
            )
        )
        seen.add(name)

    if psutil is not None:  # pragma: no branch - behaviour covered via monkeypatch in tests
        try:
            for name, addr_list in psutil.net_if_addrs().items():  # type: ignore[attr-defined]
                ip_addrs: List[InterfaceAddress] = []
                hardware: Optional[str] = None
                for entry in addr_list:
                    family = getattr(entry, "family", None)
                    address = getattr(entry, "address", "")
                    if not address:
                        continue
                    if family in _link_families():
                        hardware = address
                        continue
                    if family not in _ip_families():
                        continue
                    ip_addrs.append(
                        InterfaceAddress(
                            address=address,
                            netmask=getattr(entry, "netmask", None),
                            broadcast=getattr(entry, "broadcast", None),
                            family=family,
                        )
                    )
                is_loop = _is_loopback(name, ip_addrs)
                _append_device(name, ip_addrs, hardware, is_loop)
        except Exception:  # pragma: no cover - defensive logging only
            logger.debug("Failed to enumerate interfaces via psutil", exc_info=True)

    if not devices:
        try:
            for _, name in socket.if_nameindex():
                if name in seen:
                    continue
                ip_addrs: List[InterfaceAddress] = []
                _append_device(name, ip_addrs, None, _is_loopback(name, ip_addrs))
        except OSError:  # pragma: no cover - platform dependent
            logger.debug("socket.if_nameindex() failed", exc_info=True)

    devices.sort(key=lambda dev: dev.name)
    return devices


def get_hardware_address(interface: str) -> Optional[str]:
    """Return the MAC address for *interface*, similar to PcapUtils.getHardwareAddress."""

    if psutil is None:
        return None

    try:
        entries = psutil.net_if_addrs().get(interface, [])  # type: ignore[attr-defined]
    except Exception:  # pragma: no cover - defensive logging only
        logger.debug("psutil.net_if_addrs() lookup failed", exc_info=True)
        return None

    for entry in entries:
        if getattr(entry, "family", None) in _link_families():
            address = getattr(entry, "address", "")
            return address or None
    return None


def open_live(
    interface: str,
    snaplen: int = 65_535,
    promisc: bool = True,
    timeout_ms: int = 1_000,
    **kwargs,
) -> LiveCapture:
    """Factory mirroring Pcap.openLive(), returning a configured LiveCapture."""

    return LiveCapture(
        interface,
        bpf_filter=kwargs.pop("bpf_filter", None),
        snaplen=snaplen,
        promiscuous=promisc,
        read_timeout=timeout_ms,
        **kwargs,
    )


def open_offline(
    path: str,
    *,
    read_ip4: bool = True,
    read_ip6: bool = False,
) -> PacketReader:
    """Factory mirroring Pcap.openOffline(), yielding PacketReader instances."""

    return PacketReader(path, read_ip4=read_ip4, read_ip6=read_ip6)


def _link_families() -> tuple[int, ...]:
    fams: List[int] = []
    if hasattr(socket, "AF_PACKET"):
        fams.append(socket.AF_PACKET)  # type: ignore[attr-defined]
    if hasattr(socket, "AF_LINK"):
        fams.append(socket.AF_LINK)  # type: ignore[attr-defined]
    if psutil is not None and hasattr(psutil, "AF_LINK"):
        fams.append(psutil.AF_LINK)  # type: ignore[attr-defined]
    return tuple(fams)


def _ip_families() -> tuple[int, ...]:
    fams = [socket.AF_INET]
    if hasattr(socket, "AF_INET6"):
        fams.append(socket.AF_INET6)
    return tuple(fams)


def _is_loopback(name: str, addresses: Sequence[InterfaceAddress]) -> bool:
    if any(addr.address.startswith("127.") for addr in addresses if addr.family == socket.AF_INET):
        return True
    if any(addr.address in {"::1", "0:0:0:0:0:0:0:1"} for addr in addresses if addr.family == getattr(socket, "AF_INET6", object())):
        return True
    return name.lower().startswith(("lo", "loopback"))


__all__ = [
    "InterfaceAddress",
    "PcapDevice",
    "list_devices",
    "get_hardware_address",
    "open_live",
    "open_offline",
]
