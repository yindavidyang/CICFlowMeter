"""Python port of cic.cs.unb.ca.jnetpcap.BasicPacketInfo."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .id_generator import IdGenerator
from .utils import format_ip


@dataclass
class BasicPacketInfo:
    src: bytes
    dst: bytes
    src_port: int
    dst_port: int
    protocol: int
    timestamp: int
    generator: IdGenerator
    id: int = field(init=False)
    payload_bytes: int = 0
    header_bytes: int = 0
    tcp_window: int = 0
    payload_packet_count: int = 0
    flag_fin: bool = False
    flag_psh: bool = False
    flag_urg: bool = False
    flag_ece: bool = False
    flag_syn: bool = False
    flag_ack: bool = False
    flag_cwr: bool = False
    flag_rst: bool = False
    _flow_id: Optional[str] = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        self.id = self.generator.next_id()
        # Defensive copies keep the Java semantics.
        self.src = bytes(self.src)
        self.dst = bytes(self.dst)
        self.generate_flow_id()

    # Flow id helpers -----------------------------------------------------
    def generate_flow_id(self) -> str:
        forward = True
        for left, right in zip(self.src, self.dst):
            if left != right:
                if left > right:
                    forward = False
                break
        if forward:
            flow = f"{format_ip(self.src)}-{format_ip(self.dst)}-{self.src_port}-{self.dst_port}-{self.protocol}"
        else:
            flow = f"{format_ip(self.dst)}-{format_ip(self.src)}-{self.dst_port}-{self.src_port}-{self.protocol}"
        self._flow_id = flow
        return flow

    def fwd_flow_id(self) -> str:
        flow = f"{format_ip(self.src)}-{format_ip(self.dst)}-{self.src_port}-{self.dst_port}-{self.protocol}"
        self._flow_id = flow
        return flow

    def bwd_flow_id(self) -> str:
        flow = f"{format_ip(self.dst)}-{format_ip(self.src)}-{self.dst_port}-{self.src_port}-{self.protocol}"
        self._flow_id = flow
        return flow

    # Accessors -----------------------------------------------------------
    def get_flow_id(self) -> str:
        if self._flow_id is None:
            return self.generate_flow_id()
        return self._flow_id

    def set_flow_id(self, flow_id: str) -> None:
        self._flow_id = flow_id

    def is_forward_packet(self, source_ip: bytes) -> bool:
        return bytes(source_ip) == self.src

    def get_payload_packet(self) -> int:
        self.payload_packet_count += 1
        return self.payload_packet_count

    # Flag setters --------------------------------------------------------
    def set_flag_fin(self, value: bool) -> None:
        self.flag_fin = value

    def has_flag_fin(self) -> bool:
        return self.flag_fin

    def set_flag_psh(self, value: bool) -> None:
        self.flag_psh = value

    def has_flag_psh(self) -> bool:
        return self.flag_psh

    def set_flag_urg(self, value: bool) -> None:
        self.flag_urg = value

    def has_flag_urg(self) -> bool:
        return self.flag_urg

    def set_flag_ece(self, value: bool) -> None:
        self.flag_ece = value

    def has_flag_ece(self) -> bool:
        return self.flag_ece

    def set_flag_syn(self, value: bool) -> None:
        self.flag_syn = value

    def has_flag_syn(self) -> bool:
        return self.flag_syn

    def set_flag_ack(self, value: bool) -> None:
        self.flag_ack = value

    def has_flag_ack(self) -> bool:
        return self.flag_ack

    def set_flag_cwr(self, value: bool) -> None:
        self.flag_cwr = value

    def has_flag_cwr(self) -> bool:
        return self.flag_cwr

    def set_flag_rst(self, value: bool) -> None:
        self.flag_rst = value

    def has_flag_rst(self) -> bool:
        return self.flag_rst


__all__ = ["BasicPacketInfo"]
