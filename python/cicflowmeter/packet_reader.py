"""PCAP ingestion layer mirroring the Java PacketReader semantics."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import IO, Iterator, Optional, Tuple, Union

import dpkt
from dpkt.ethernet import VLANtag8021Q

from .basic_packet_info import BasicPacketInfo
from .id_generator import IdGenerator

logger = logging.getLogger(__name__)

MICROS_PER_SECOND = 1_000_000


class PacketReader:
    """Iterates over BasicPacketInfo instances decoded from a PCAP capture."""

    def __init__(
        self,
        pcap_path: Union[str, Path],
        *,
        read_ip4: bool = True,
        read_ip6: bool = False,
    ) -> None:
        path = Path(pcap_path)
        if not path.is_file():
            raise FileNotFoundError(f"PCAP file does not exist: {path}")
        if not read_ip4 and not read_ip6:
            raise ValueError("At least one of read_ip4 or read_ip6 must be enabled")

        self.path = path
        self.read_ip4 = read_ip4
        self.read_ip6 = read_ip6

        self._file: Optional[IO[bytes]] = None
        self._pcap: Optional[dpkt.pcap.Reader] = None
        self._packet_iter: Optional[Iterator[Tuple[float, bytes]]] = None

        self._generator = IdGenerator()
        self._first_packet_ts: Optional[int] = None
        self._last_packet_ts: Optional[int] = None

    # ------------------------------------------------------------------
    def __enter__(self) -> "PacketReader":
        self._open()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # type: ignore[override]
        self.close()

    # ------------------------------------------------------------------
    def close(self) -> None:
        if self._pcap is not None:
            self._pcap = None
        if self._file is not None:
            try:
                self._file.close()
            except OSError:
                logger.debug("Failed to close PCAP file", exc_info=True)
            finally:
                self._file = None
        self._packet_iter = None

    # ------------------------------------------------------------------
    def __iter__(self) -> Iterator[BasicPacketInfo]:
        while True:
            packet = self.next_packet()
            if packet is None:
                break
            yield packet

    def next_packet(self) -> Optional[BasicPacketInfo]:
        self._ensure_iter()
        assert self._packet_iter is not None

        for ts, buf in self._packet_iter:
            packet = self._decode_packet(ts, buf)
            if packet is not None:
                return packet
        return None

    # ------------------------------------------------------------------
    @property
    def first_packet_timestamp(self) -> Optional[int]:
        return self._first_packet_ts

    @property
    def last_packet_timestamp(self) -> Optional[int]:
        return self._last_packet_ts

    # ------------------------------------------------------------------
    def _ensure_iter(self) -> None:
        if self._pcap is None or self._packet_iter is None:
            self._open()
            assert self._pcap is not None
            self._packet_iter = iter(self._pcap)

    def _open(self) -> None:
        if self._pcap is not None:
            return
        try:
            self._file = self.path.open("rb")
            self._pcap = dpkt.pcap.Reader(self._file)
        except (OSError, dpkt.dpkt.NeedData) as exc:
            self.close()
            raise RuntimeError(f"Failed to open PCAP file: {self.path}") from exc

    # ------------------------------------------------------------------
    def _decode_packet(self, timestamp: float, frame: bytes) -> Optional[BasicPacketInfo]:
        try:
            ethernet = dpkt.ethernet.Ethernet(frame)
        except (dpkt.UnpackError, ValueError):
            logger.debug("Skipping undecodable Ethernet frame", exc_info=True)
            return None

        payload = ethernet.data
        if isinstance(payload, VLANtag8021Q):
            payload = payload.data

        ip_payload = payload
        if isinstance(ip_payload, dpkt.ip.IP):
            if not self.read_ip4:
                return None
            return self._decode_ipv4_packet(timestamp, ip_payload)
        if isinstance(ip_payload, dpkt.ip6.IP6):
            if not self.read_ip6:
                return None
            return self._decode_ipv6_packet(timestamp, ip_payload)

        return None

    def _decode_ipv4_packet(self, timestamp: float, packet: dpkt.ip.IP) -> Optional[BasicPacketInfo]:
        transport = packet.data
        if isinstance(transport, dpkt.tcp.TCP):
            info = self._build_packet_info(timestamp, packet.src, packet.dst, packet.p, transport)
            if info is not None:
                self._populate_tcp_fields(info, transport)
            return info
        if isinstance(transport, dpkt.udp.UDP):
            return self._build_packet_info(timestamp, packet.src, packet.dst, packet.p, transport)
        return None

    def _decode_ipv6_packet(self, timestamp: float, packet: dpkt.ip6.IP6) -> Optional[BasicPacketInfo]:
        transport = packet.data
        if isinstance(transport, dpkt.tcp.TCP):
            info = self._build_packet_info(timestamp, packet.src, packet.dst, packet.nxt, transport)
            if info is not None:
                self._populate_tcp_fields(info, transport)
            return info
        if isinstance(transport, dpkt.udp.UDP):
            return self._build_packet_info(timestamp, packet.src, packet.dst, packet.nxt, transport)
        return None

    # ------------------------------------------------------------------
    def _build_packet_info(
        self,
        timestamp: float,
        src: bytes,
        dst: bytes,
        protocol: int,
        transport: Union[dpkt.tcp.TCP, dpkt.udp.UDP],
    ) -> Optional[BasicPacketInfo]:
        payload_len = len(transport.data)
        if isinstance(transport, dpkt.tcp.TCP):
            header_len = (transport.off << 2) if transport.off else 0
        elif isinstance(transport, dpkt.udp.UDP):
            header_len = 8 if transport.ulen >= 8 else max(transport.ulen, 0)
        else:
            header_len = 0
        micros = int(timestamp * MICROS_PER_SECOND)

        self._register_timestamp(micros)

        packet_info = BasicPacketInfo(
            src=src,
            dst=dst,
            src_port=getattr(transport, "sport", 0),
            dst_port=getattr(transport, "dport", 0),
            protocol=protocol,
            timestamp=micros,
            generator=self._generator,
        )
        packet_info.payload_bytes = payload_len
        packet_info.header_bytes = header_len

        if isinstance(transport, dpkt.udp.UDP):
            return packet_info

        if isinstance(transport, dpkt.tcp.TCP):
            packet_info.tcp_window = transport.win
            return packet_info

        return None

    def _populate_tcp_fields(self, packet_info: BasicPacketInfo, tcp: dpkt.tcp.TCP) -> None:
        flags = tcp.flags
        packet_info.set_flag_fin(bool(flags & dpkt.tcp.TH_FIN))
        packet_info.set_flag_syn(bool(flags & dpkt.tcp.TH_SYN))
        packet_info.set_flag_rst(bool(flags & dpkt.tcp.TH_RST))
        packet_info.set_flag_psh(bool(flags & dpkt.tcp.TH_PUSH))
        packet_info.set_flag_ack(bool(flags & dpkt.tcp.TH_ACK))
        packet_info.set_flag_urg(bool(flags & dpkt.tcp.TH_URG))
        packet_info.set_flag_cwr(bool(flags & dpkt.tcp.TH_CWR))
        packet_info.set_flag_ece(bool(flags & dpkt.tcp.TH_ECE))

    def _register_timestamp(self, micros: int) -> None:
        if self._first_packet_ts is None:
            self._first_packet_ts = micros
        self._last_packet_ts = micros


__all__ = ["PacketReader"]
