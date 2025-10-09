"""Real-time packet capture bridging Scapy sniffing with the flow generator."""

from __future__ import annotations

import logging
import socket
import threading
from typing import Callable, Optional

from .basic_packet_info import BasicPacketInfo
from .flow_generator import FlowGenerator
from .id_generator import IdGenerator
from .listeners import FlowGenListener

logger = logging.getLogger(__name__)

MICROS_PER_SECOND = 1_000_000

try:  # pragma: no cover - exercised only when Scapy is available at runtime
    from scapy.all import AsyncSniffer, IP, IPv6, TCP, UDP  # type: ignore
    from scapy.packet import Packet  # type: ignore
except ImportError:  # pragma: no cover - import guard for optional dependency
    AsyncSniffer = None  # type: ignore[assignment]
    IP = IPv6 = TCP = UDP = None  # type: ignore[assignment]

    class Packet:  # type: ignore[override]
        """Fallback stub used when Scapy is not installed."""

        ...


class LiveCaptureError(RuntimeError):
    """Raised when live capture cannot be started or operated."""


class LiveCapture:
    """Capture live packets from a network interface and feed the flow generator."""

    def __init__(
        self,
        interface: str,
        *,
        bidirectional: bool = True,
        flow_timeout: int = 120_000_000,
        activity_timeout: int = 5_000_000,
        read_ip4: bool = True,
        read_ip6: bool = False,
        bpf_filter: Optional[str] = None,
        flow_listener: Optional[FlowGenListener] = None,
        status_handler: Optional[Callable[[str], None]] = None,
        snaplen: int = 65_535,
        promiscuous: bool = True,
        read_timeout: int = 1_000,
    ) -> None:
        self.interface = interface
        self.read_ip4 = read_ip4
        self.read_ip6 = read_ip6
        self.bpf_filter = bpf_filter
        self.status_handler = status_handler
        self.snaplen = snaplen
        self.promiscuous = promiscuous
        self.read_timeout_ms = read_timeout

        self.flow_generator = FlowGenerator(
            bidirectional,
            flow_timeout,
            activity_timeout,
        )
        if flow_listener is not None:
            self.flow_generator.add_flow_listener(flow_listener)

        self._id_generator = IdGenerator()
        self._lock = threading.RLock()
        self._sniffer: Optional[AsyncSniffer] = None  # type: ignore[type-var]

    # ------------------------------------------------------------------
    def start(self) -> None:
        """Start sniffing packets on the configured interface."""
        if AsyncSniffer is None:  # pragma: no cover - requires Scapy at runtime
            raise LiveCaptureError(
                "Live capture requires the optional dependency 'scapy'. "
                "Install with `pip install cicflowmeter[live]`."
            )

        with self._lock:
            if self._sniffer is not None:
                raise LiveCaptureError("Capture already running")

            sniffer = AsyncSniffer(
                iface=self.interface,
                prn=self._handle_packet,
                store=False,
                filter=self.bpf_filter,
            )
            try:
                sniffer.start()
            except Exception as exc:  # pragma: no cover - start failures depend on system
                raise LiveCaptureError(
                    f"Failed to start capture on interface '{self.interface}'"
                ) from exc

            self._sniffer = sniffer

        self._notify_status(f"listening: {self.interface}")
        logger.info("Live capture listening on %s", self.interface)

    # ------------------------------------------------------------------
    def stop(self) -> None:
        """Stop sniffing packets if the capture is running."""
        with self._lock:
            sniffer = self._sniffer
            self._sniffer = None

        if sniffer is None:
            return

        try:
            sniffer.stop()
        except Exception:  # pragma: no cover - stop failures depend on system
            logger.exception("Failed to stop live capture")

        self._notify_status(f"stopped: {self.interface}")
        logger.info("Live capture stopped on %s", self.interface)

    # ------------------------------------------------------------------
    def is_running(self) -> bool:
        with self._lock:
            return self._sniffer is not None

    # ------------------------------------------------------------------
    def _handle_packet(self, packet: Packet) -> None:  # pragma: no cover - requires Scapy at runtime
        try:
            basic_packet = self._build_packet_info(packet)
        except Exception:  # pragma: no cover - conversion errors get logged for diagnosis
            logger.exception("Failed to convert packet to BasicPacketInfo")
            return

        if basic_packet is None:
            return

        self.flow_generator.add_packet(basic_packet)

    # ------------------------------------------------------------------
    def _build_packet_info(self, packet: Packet) -> Optional[BasicPacketInfo]:
        if not hasattr(packet, "time"):
            return None

        timestamp = int(float(packet.time) * MICROS_PER_SECOND)

        if self.read_ip4 and IP is not None and packet.haslayer(IP):
            ip_layer = packet.getlayer(IP)
            return self._build_from_ip_layer(
                timestamp,
                socket.AF_INET,
                ip_layer.src,
                ip_layer.dst,
                int(ip_layer.proto),
                ip_layer.payload,
            )

        if self.read_ip6 and IPv6 is not None and packet.haslayer(IPv6):
            ip_layer = packet.getlayer(IPv6)
            return self._build_from_ip_layer(
                timestamp,
                socket.AF_INET6,
                ip_layer.src,
                ip_layer.dst,
                int(ip_layer.nh),
                ip_layer.payload,
            )

        return None

    def _build_from_ip_layer(
        self,
        timestamp: int,
        family: int,
        src: str,
        dst: str,
        protocol: int,
        transport,
    ) -> Optional[BasicPacketInfo]:
        try:
            src_bytes = socket.inet_pton(family, src)
            dst_bytes = socket.inet_pton(family, dst)
        except OSError:
            logger.debug("Skipping packet with unparsable address", exc_info=True)
            return None

        if TCP is not None and isinstance(transport, TCP):
            packet_info = self._build_tcp_packet(timestamp, src_bytes, dst_bytes, protocol, transport)
        elif UDP is not None and isinstance(transport, UDP):
            packet_info = self._build_udp_packet(timestamp, src_bytes, dst_bytes, protocol, transport)
        else:
            return None

        return packet_info

    def _build_tcp_packet(
        self,
        timestamp: int,
        src: bytes,
        dst: bytes,
        protocol: int,
        tcp: TCP,
    ) -> BasicPacketInfo:
        packet_info = BasicPacketInfo(
            src=src,
            dst=dst,
            src_port=int(getattr(tcp, "sport", 0)),
            dst_port=int(getattr(tcp, "dport", 0)),
            protocol=protocol,
            timestamp=timestamp,
            generator=self._id_generator,
        )

        payload = getattr(tcp, "payload", b"")
        payload_len = len(bytes(payload)) if payload else 0
        packet_info.payload_bytes = payload_len
        try:
            segment_len = len(bytes(tcp))
        except Exception:
            segment_len = payload_len
        header_len = max(segment_len - payload_len, 0)
        packet_info.header_bytes = header_len
        packet_info.tcp_window = int(getattr(tcp, "window", getattr(tcp, "win", 0)))

        flags = int(getattr(tcp, "flags", 0))
        packet_info.set_flag_fin(bool(flags & 0x01))
        packet_info.set_flag_syn(bool(flags & 0x02))
        packet_info.set_flag_rst(bool(flags & 0x04))
        packet_info.set_flag_psh(bool(flags & 0x08))
        packet_info.set_flag_ack(bool(flags & 0x10))
        packet_info.set_flag_urg(bool(flags & 0x20))
        packet_info.set_flag_ece(bool(flags & 0x40))
        packet_info.set_flag_cwr(bool(flags & 0x80))

        return packet_info

    def _build_udp_packet(
        self,
        timestamp: int,
        src: bytes,
        dst: bytes,
        protocol: int,
        udp: UDP,
    ) -> BasicPacketInfo:
        packet_info = BasicPacketInfo(
            src=src,
            dst=dst,
            src_port=int(getattr(udp, "sport", 0)),
            dst_port=int(getattr(udp, "dport", 0)),
            protocol=protocol,
            timestamp=timestamp,
            generator=self._id_generator,
        )

        payload = getattr(udp, "payload", b"")
        payload_len = len(bytes(payload)) if payload else 0
        packet_info.payload_bytes = payload_len
        try:
            datagram_len = len(bytes(udp))
        except Exception:
            datagram_len = payload_len + 8
        header_len = max(datagram_len - payload_len, 0)
        packet_info.header_bytes = header_len

        return packet_info

    # ------------------------------------------------------------------
    def _notify_status(self, message: str) -> None:
        if self.status_handler is not None:
            try:
                self.status_handler(message)
            except Exception:  # pragma: no cover - user supplied handler
                logger.exception("Status handler raised an exception")


__all__ = ["LiveCapture", "LiveCaptureError"]
