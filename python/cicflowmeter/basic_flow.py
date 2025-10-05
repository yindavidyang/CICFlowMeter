"""Python port of cic.cs.unb.ca.jnetpcap.BasicFlow."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

from .basic_packet_info import BasicPacketInfo
from .date_formatter import convert_milliseconds_to_string, parse_date_from_long
from .summary_statistics import SummaryStatistics
from .utils import format_ip


@dataclass
class MutableInt:
    value: int = 0

    def increment(self) -> None:
        self.value += 1


class BasicFlow:
    separator = ","

    def __init__(
        self,
        is_bidirectional: bool,
        packet: BasicPacketInfo,
        activity_timeout: int,
        flow_src: Optional[bytes] = None,
        flow_dst: Optional[bytes] = None,
        flow_src_port: Optional[int] = None,
        flow_dst_port: Optional[int] = None,
    ) -> None:
        self.activity_timeout = activity_timeout
        self.init_parameters()
        self.is_bidirectional = is_bidirectional
        self.first_packet(packet)
        if flow_src is not None:
            self.src = bytes(flow_src)
        if flow_dst is not None:
            self.dst = bytes(flow_dst)
        if flow_src_port is not None:
            self.src_port = flow_src_port
        if flow_dst_port is not None:
            self.dst_port = flow_dst_port

    # ------------------------------------------------------------------
    def init_parameters(self) -> None:
        self.forward: List[BasicPacketInfo] = []
        self.backward: List[BasicPacketInfo] = []
        self.flow_iat = SummaryStatistics()
        self.forward_iat = SummaryStatistics()
        self.backward_iat = SummaryStatistics()
        self.flow_active = SummaryStatistics()
        self.flow_idle = SummaryStatistics()
        self.flow_length_stats = SummaryStatistics()
        self.fwd_pkt_stats = SummaryStatistics()
        self.bwd_pkt_stats = SummaryStatistics()
        self.flag_counts: Dict[str, MutableInt] = {}
        self.init_flags()
        self.forward_bytes = 0
        self.backward_bytes = 0
        self.f_header_bytes = 0
        self.b_header_bytes = 0
        self.start_active_time = 0
        self.end_active_time = 0
        self.src: bytes = b""
        self.dst: bytes = b""
        self.src_port: int = 0
        self.dst_port: int = 0
        self.protocol: int = 0
        self.flow_id: Optional[str] = None
        self.flow_start_time = 0
        self.flow_last_seen = 0
        self.forward_last_seen = 0
        self.backward_last_seen = 0
        self.fpsh_cnt = 0
        self.bpsh_cnt = 0
        self.furg_cnt = 0
        self.burg_cnt = 0
        self.ffin_cnt = 0
        self.bfin_cnt = 0
        self.act_data_pkt_forward = 0
        self.min_seg_size_forward = float("inf")
        self.init_win_bytes_forward = 0
        self.init_win_bytes_backward = 0
        # Subflow helpers
        self.sf_last_packet_ts = -1
        self.sf_count = 0
        self.sf_ac_helper = -1
        # Bulk helpers (forward)
        self._fbulk_duration = 0
        self._fbulk_packet_count = 0
        self._fbulk_size_total = 0
        self._fbulk_state_count = 0
        self._fbulk_packet_count_helper = 0
        self._fbulk_start_helper = 0
        self._fbulk_size_helper = 0
        self._flast_bulk_ts = 0
        # Bulk helpers (backward)
        self._bbulk_duration = 0
        self._bbulk_packet_count = 0
        self._bbulk_size_total = 0
        self._bbulk_state_count = 0
        self._bbulk_packet_count_helper = 0
        self._bbulk_start_helper = 0
        self._bbulk_size_helper = 0
        self._blast_bulk_ts = 0

    # ------------------------------------------------------------------
    def first_packet(self, packet: BasicPacketInfo) -> None:
        self.update_flow_bulk(packet)
        self.detect_update_subflows(packet)
        self.check_flags(packet)
        self.flow_start_time = packet.timestamp
        self.flow_last_seen = packet.timestamp
        self.start_active_time = packet.timestamp
        self.end_active_time = packet.timestamp
        self.flow_length_stats.add_value(float(packet.payload_bytes))

        if not self.src:
            self.src = packet.src
            self.src_port = packet.src_port
        if not self.dst:
            self.dst = packet.dst
            self.dst_port = packet.dst_port

        if packet.src == self.src:
            self.min_seg_size_forward = packet.header_bytes
            self.init_win_bytes_forward = packet.tcp_window
            self.flow_length_stats.add_value(float(packet.payload_bytes))
            self.fwd_pkt_stats.add_value(float(packet.payload_bytes))
            self.f_header_bytes = packet.header_bytes
            self.forward_last_seen = packet.timestamp
            self.forward_bytes += packet.payload_bytes
            self.forward.append(packet)
            if packet.flag_psh:
                self.fpsh_cnt += 1
            if packet.flag_urg:
                self.furg_cnt += 1
        else:
            self.init_win_bytes_backward = packet.tcp_window
            self.flow_length_stats.add_value(float(packet.payload_bytes))
            self.bwd_pkt_stats.add_value(float(packet.payload_bytes))
            self.b_header_bytes = packet.header_bytes
            self.backward_last_seen = packet.timestamp
            self.backward_bytes += packet.payload_bytes
            self.backward.append(packet)
            if packet.flag_psh:
                self.bpsh_cnt += 1
            if packet.flag_urg:
                self.burg_cnt += 1

        self.protocol = packet.protocol
        self.flow_id = packet.get_flow_id()

    # ------------------------------------------------------------------
    def add_packet(self, packet: BasicPacketInfo) -> None:
        self.update_flow_bulk(packet)
        self.detect_update_subflows(packet)
        self.check_flags(packet)
        current_timestamp = packet.timestamp

        if self.is_bidirectional:
            self.flow_length_stats.add_value(float(packet.payload_bytes))
            if packet.src == self.src:
                if packet.payload_bytes >= 1:
                    self.act_data_pkt_forward += 1
                self.fwd_pkt_stats.add_value(float(packet.payload_bytes))
                self.f_header_bytes += packet.header_bytes
                self.forward.append(packet)
                self.forward_bytes += packet.payload_bytes
                if len(self.forward) > 1:
                    self.forward_iat.add_value(current_timestamp - self.forward_last_seen)
                self.forward_last_seen = current_timestamp
                self.min_seg_size_forward = min(self.min_seg_size_forward, packet.header_bytes)
            else:
                self.bwd_pkt_stats.add_value(float(packet.payload_bytes))
                self.init_win_bytes_backward = packet.tcp_window
                self.b_header_bytes += packet.header_bytes
                self.backward.append(packet)
                self.backward_bytes += packet.payload_bytes
                if len(self.backward) > 1:
                    self.backward_iat.add_value(current_timestamp - self.backward_last_seen)
                self.backward_last_seen = current_timestamp
        else:
            if packet.payload_bytes >= 1:
                self.act_data_pkt_forward += 1
            self.fwd_pkt_stats.add_value(float(packet.payload_bytes))
            self.flow_length_stats.add_value(float(packet.payload_bytes))
            self.f_header_bytes += packet.header_bytes
            self.forward.append(packet)
            self.forward_bytes += packet.payload_bytes
            if self.forward_last_seen:
                self.forward_iat.add_value(current_timestamp - self.forward_last_seen)
            self.forward_last_seen = current_timestamp
            self.min_seg_size_forward = min(self.min_seg_size_forward, packet.header_bytes)

        self.flow_iat.add_value(packet.timestamp - self.flow_last_seen)
        self.flow_last_seen = packet.timestamp

    # ------------------------------------------------------------------
    def init_flags(self) -> None:
        for key in ("FIN", "SYN", "RST", "PSH", "ACK", "URG", "CWR", "ECE"):
            self.flag_counts[key] = MutableInt()

    def check_flags(self, packet: BasicPacketInfo) -> None:
        if packet.flag_fin:
            self.flag_counts["FIN"].increment()
        if packet.flag_syn:
            self.flag_counts["SYN"].increment()
        if packet.flag_rst:
            self.flag_counts["RST"].increment()
        if packet.flag_psh:
            self.flag_counts["PSH"].increment()
        if packet.flag_ack:
            self.flag_counts["ACK"].increment()
        if packet.flag_urg:
            self.flag_counts["URG"].increment()
        if packet.flag_cwr:
            self.flag_counts["CWR"].increment()
        if packet.flag_ece:
            self.flag_counts["ECE"].increment()

    # ------------------------------------------------------------------
    def detect_update_subflows(self, packet: BasicPacketInfo) -> None:
        if self.sf_last_packet_ts == -1:
            self.sf_last_packet_ts = packet.timestamp
            self.sf_ac_helper = packet.timestamp
        if ((packet.timestamp - self.sf_last_packet_ts) / 1_000_000.0) > 1.0:
            self.sf_count += 1
            self.update_active_idle_time(packet.timestamp, self.activity_timeout)
            self.sf_ac_helper = packet.timestamp
        self.sf_last_packet_ts = packet.timestamp

    def update_flow_bulk(self, packet: BasicPacketInfo) -> None:
        if packet.src == self.src:
            self.update_forward_bulk(packet, self._blast_bulk_ts)
        else:
            self.update_backward_bulk(packet, self._flast_bulk_ts)

    def update_forward_bulk(self, packet: BasicPacketInfo, ts_of_last_bulk_in_other: int) -> None:
        size = packet.payload_bytes
        if ts_of_last_bulk_in_other > self._fbulk_start_helper:
            self._fbulk_start_helper = 0
        if size <= 0:
            return
        packet.get_payload_packet()
        if self._fbulk_start_helper == 0:
            self._fbulk_start_helper = packet.timestamp
            self._fbulk_packet_count_helper = 1
            self._fbulk_size_helper = size
            self._flast_bulk_ts = packet.timestamp
        else:
            if ((packet.timestamp - self._flast_bulk_ts) / 1_000_000.0) > 1.0:
                self._fbulk_start_helper = packet.timestamp
                self._flast_bulk_ts = packet.timestamp
                self._fbulk_packet_count_helper = 1
                self._fbulk_size_helper = size
            else:
                self._fbulk_packet_count_helper += 1
                self._fbulk_size_helper += size
                if self._fbulk_packet_count_helper == 4:
                    self._fbulk_state_count += 1
                    self._fbulk_packet_count += self._fbulk_packet_count_helper
                    self._fbulk_size_total += self._fbulk_size_helper
                    self._fbulk_duration += packet.timestamp - self._fbulk_start_helper
                elif self._fbulk_packet_count_helper > 4:
                    self._fbulk_packet_count += 1
                    self._fbulk_size_total += size
                    self._fbulk_duration += packet.timestamp - self._flast_bulk_ts
                self._flast_bulk_ts = packet.timestamp

    def update_backward_bulk(self, packet: BasicPacketInfo, ts_of_last_bulk_in_other: int) -> None:
        size = packet.payload_bytes
        if ts_of_last_bulk_in_other > self._bbulk_start_helper:
            self._bbulk_start_helper = 0
        if size <= 0:
            return
        packet.get_payload_packet()
        if self._bbulk_start_helper == 0:
            self._bbulk_start_helper = packet.timestamp
            self._bbulk_packet_count_helper = 1
            self._bbulk_size_helper = size
            self._blast_bulk_ts = packet.timestamp
        else:
            if ((packet.timestamp - self._blast_bulk_ts) / 1_000_000.0) > 1.0:
                self._bbulk_start_helper = packet.timestamp
                self._blast_bulk_ts = packet.timestamp
                self._bbulk_packet_count_helper = 1
                self._bbulk_size_helper = size
            else:
                self._bbulk_packet_count_helper += 1
                self._bbulk_size_helper += size
                if self._bbulk_packet_count_helper == 4:
                    self._bbulk_state_count += 1
                    self._bbulk_packet_count += self._bbulk_packet_count_helper
                    self._bbulk_size_total += self._bbulk_size_helper
                    self._bbulk_duration += packet.timestamp - self._bbulk_start_helper
                elif self._bbulk_packet_count_helper > 4:
                    self._bbulk_packet_count += 1
                    self._bbulk_size_total += size
                    self._bbulk_duration += packet.timestamp - self._blast_bulk_ts
                self._blast_bulk_ts = packet.timestamp

    # ------------------------------------------------------------------
    def update_active_idle_time(self, current_time: int, threshold: int) -> None:
        if (current_time - self.end_active_time) > threshold:
            if (self.end_active_time - self.start_active_time) > 0:
                self.flow_active.add_value(float(self.end_active_time - self.start_active_time))
            self.flow_idle.add_value(float(current_time - self.end_active_time))
            self.start_active_time = current_time
            self.end_active_time = current_time
        else:
            self.end_active_time = current_time

    def end_active_idle_time(self, current_time: int, threshold: int, flow_timeout: int, is_flag_end: bool) -> None:
        if (self.end_active_time - self.start_active_time) > 0:
            self.flow_active.add_value(float(self.end_active_time - self.start_active_time))
        if (not is_flag_end) and ((flow_timeout - (self.end_active_time - self.flow_start_time)) > 0):
            self.flow_idle.add_value(float(flow_timeout - (self.end_active_time - self.flow_start_time)))

    # ------------------------------------------------------------------
    def packet_count(self) -> int:
        if self.is_bidirectional:
            return len(self.forward) + len(self.backward)
        return len(self.forward)

    def get_forward(self) -> List[BasicPacketInfo]:
        return list(self.forward)

    def get_backward(self) -> List[BasicPacketInfo]:
        return list(self.backward)

    def get_src(self) -> bytes:
        return bytes(self.src)

    def get_dst(self) -> bytes:
        return bytes(self.dst)

    def get_src_port(self) -> int:
        return self.src_port

    def get_dst_port(self) -> int:
        return self.dst_port

    def get_protocol(self) -> int:
        return self.protocol

    def get_protocol_str(self) -> str:
        if self.protocol == 6:
            return "TCP"
        if self.protocol == 17:
            return "UDP"
        return "UNKNOWN"

    def set_protocol(self, protocol: int) -> None:
        self.protocol = protocol

    def get_flow_start_time(self) -> int:
        return self.flow_start_time

    def set_flow_start_time(self, flow_start_time: int) -> None:
        self.flow_start_time = flow_start_time

    def get_flow_id(self) -> Optional[str]:
        return self.flow_id

    def set_flow_id(self, flow_id: str) -> None:
        self.flow_id = flow_id

    def get_last_seen(self) -> int:
        return self.flow_last_seen

    def get_start_active_time(self) -> int:
        return self.start_active_time

    def get_end_active_time(self) -> int:
        return self.end_active_time

    def get_src_ip(self) -> str:
        return format_ip(self.src)

    def get_dst_ip(self) -> str:
        return format_ip(self.dst)

    def get_timestamp(self) -> str:
        return parse_date_from_long(self.flow_start_time // 1000, "%d/%m/%Y %I:%M:%S")

    def get_flow_duration(self) -> int:
        return self.flow_last_seen - self.flow_start_time

    def get_total_fwd_packets(self) -> int:
        return self.fwd_pkt_stats.getN()

    def get_total_backward_packets(self) -> int:
        return self.bwd_pkt_stats.getN()

    def get_total_length_of_fwd_packets(self) -> float:
        return self.fwd_pkt_stats.getSum()

    def get_total_length_of_bwd_packets(self) -> float:
        return self.bwd_pkt_stats.getSum()

    def get_fwd_packet_length_max(self) -> float:
        return self.fwd_pkt_stats.getMax()

    def get_fwd_packet_length_min(self) -> float:
        return self.fwd_pkt_stats.getMin()

    def get_fwd_packet_length_mean(self) -> float:
        return self.fwd_pkt_stats.getMean()

    def get_fwd_packet_length_std(self) -> float:
        return self.fwd_pkt_stats.getStandardDeviation()

    def get_bwd_packet_length_max(self) -> float:
        return self.bwd_pkt_stats.getMax()

    def get_bwd_packet_length_min(self) -> float:
        return self.bwd_pkt_stats.getMin()

    def get_bwd_packet_length_mean(self) -> float:
        return self.bwd_pkt_stats.getMean()

    def get_bwd_packet_length_std(self) -> float:
        return self.bwd_pkt_stats.getStandardDeviation()

    def get_flow_bytes_per_sec(self) -> float:
        duration = self.get_flow_duration()
        if duration == 0:
            return 0.0
        return (self.forward_bytes + self.backward_bytes) / (duration / 1_000_000.0)

    def get_flow_packets_per_sec(self) -> float:
        duration = self.get_flow_duration()
        if duration == 0:
            return 0.0
        return self.packet_count() / (duration / 1_000_000.0)

    def get_flow_iat(self) -> SummaryStatistics:
        return self.flow_iat

    def get_fwd_iat_total(self) -> float:
        return self.forward_iat.getSum() if len(self.forward) > 1 else 0.0

    def get_fwd_iat_mean(self) -> float:
        return self.forward_iat.getMean() if len(self.forward) > 1 else 0.0

    def get_fwd_iat_std(self) -> float:
        return self.forward_iat.getStandardDeviation() if len(self.forward) > 1 else 0.0

    def get_fwd_iat_max(self) -> float:
        return self.forward_iat.getMax() if len(self.forward) > 1 else 0.0

    def get_fwd_iat_min(self) -> float:
        return self.forward_iat.getMin() if len(self.forward) > 1 else 0.0

    def get_bwd_iat_total(self) -> float:
        return self.backward_iat.getSum() if len(self.backward) > 1 else 0.0

    def get_bwd_iat_mean(self) -> float:
        return self.backward_iat.getMean() if len(self.backward) > 1 else 0.0

    def get_bwd_iat_std(self) -> float:
        return self.backward_iat.getStandardDeviation() if len(self.backward) > 1 else 0.0

    def get_bwd_iat_max(self) -> float:
        return self.backward_iat.getMax() if len(self.backward) > 1 else 0.0

    def get_bwd_iat_min(self) -> float:
        return self.backward_iat.getMin() if len(self.backward) > 1 else 0.0

    def get_fwd_psh_flags(self) -> int:
        return self.fpsh_cnt

    def get_bwd_psh_flags(self) -> int:
        return self.bpsh_cnt

    def get_fwd_urg_flags(self) -> int:
        return self.furg_cnt

    def get_bwd_urg_flags(self) -> int:
        return self.burg_cnt

    def get_fwd_fin_flags(self) -> int:
        return self.ffin_cnt

    def get_bwd_fin_flags(self) -> int:
        return self.bfin_cnt

    def set_fwd_fin_flags(self) -> int:
        self.ffin_cnt += 1
        return self.ffin_cnt

    def set_bwd_fin_flags(self) -> int:
        self.bfin_cnt += 1
        return self.bfin_cnt

    def get_fwd_header_length(self) -> int:
        return self.f_header_bytes

    def get_bwd_header_length(self) -> int:
        return self.b_header_bytes

    def get_min_packet_length(self) -> float:
        return self.flow_length_stats.getMin()

    def get_max_packet_length(self) -> float:
        return self.flow_length_stats.getMax()

    def get_packet_length_mean(self) -> float:
        return self.flow_length_stats.getMean()

    def get_packet_length_std(self) -> float:
        return self.flow_length_stats.getStandardDeviation()

    def get_packet_length_variance(self) -> float:
        return self.flow_length_stats.getVariance()

    def get_flag_count(self, key: str) -> int:
        return self.flag_counts[key].value

    def get_init_win_bytes_forward(self) -> int:
        return self.init_win_bytes_forward

    def get_init_win_bytes_backward(self) -> int:
        return self.init_win_bytes_backward

    def get_act_data_pkt_forward(self) -> int:
        return self.act_data_pkt_forward

    def get_min_seg_size_forward(self) -> float:
        return 0.0 if self.min_seg_size_forward == float("inf") else self.min_seg_size_forward

    def get_flow_active_mean(self) -> float:
        return self.flow_active.getMean()

    def get_flow_active_std(self) -> float:
        return self.flow_active.getStandardDeviation()

    def get_flow_active_max(self) -> float:
        return self.flow_active.getMax()

    def get_flow_active_min(self) -> float:
        return self.flow_active.getMin()

    def get_flow_idle_mean(self) -> float:
        return self.flow_idle.getMean()

    def get_flow_idle_std(self) -> float:
        return self.flow_idle.getStandardDeviation()

    def get_flow_idle_max(self) -> float:
        return self.flow_idle.getMax()

    def get_flow_idle_min(self) -> float:
        return self.flow_idle.getMin()

    def get_down_up_ratio(self) -> float:
        if self.forward:
            return len(self.backward) / float(len(self.forward))
        return 0.0

    def get_avg_packet_size(self) -> float:
        total_packets = self.packet_count()
        if total_packets == 0:
            return 0.0
        return self.flow_length_stats.getSum() / total_packets

    def f_avg_segment_size(self) -> float:
        if not self.forward:
            return 0.0
        return self.fwd_pkt_stats.getSum() / len(self.forward)

    def b_avg_segment_size(self) -> float:
        if not self.backward:
            return 0.0
        return self.bwd_pkt_stats.getSum() / len(self.backward)

    # Bulk getters ------------------------------------------------------
    def get_sflow_fbytes(self) -> int:
        if self.sf_count <= 0:
            return 0
        return int(self.forward_bytes / self.sf_count)

    def get_sflow_fpackets(self) -> int:
        if self.sf_count <= 0:
            return 0
        return int(len(self.forward) / self.sf_count)

    def get_sflow_bbytes(self) -> int:
        if self.sf_count <= 0:
            return 0
        return int(self.backward_bytes / self.sf_count)

    def get_sflow_bpackets(self) -> int:
        if self.sf_count <= 0:
            return 0
        return int(len(self.backward) / self.sf_count)

    def get_fbulk_state_count(self) -> int:
        return self._fbulk_state_count

    def get_fbulk_size_total(self) -> int:
        return self._fbulk_size_total

    def get_fbulk_packet_count(self) -> int:
        return self._fbulk_packet_count

    def get_fbulk_duration(self) -> int:
        return self._fbulk_duration

    def get_fbulk_duration_in_second(self) -> float:
        return self._fbulk_duration / 1_000_000.0

    def get_f_avg_bytes_per_bulk(self) -> int:
        if self._fbulk_state_count == 0:
            return 0
        return int(self._fbulk_size_total / self._fbulk_state_count)

    def get_f_avg_packets_per_bulk(self) -> int:
        if self._fbulk_state_count == 0:
            return 0
        return int(self._fbulk_packet_count / self._fbulk_state_count)

    def get_f_avg_bulk_rate(self) -> int:
        if self._fbulk_duration == 0:
            return 0
        return int(self._fbulk_size_total / self.get_fbulk_duration_in_second())

    def get_bbulk_state_count(self) -> int:
        return self._bbulk_state_count

    def get_bbulk_size_total(self) -> int:
        return self._bbulk_size_total

    def get_bbulk_packet_count(self) -> int:
        return self._bbulk_packet_count

    def get_bbulk_duration(self) -> int:
        return self._bbulk_duration

    def get_bbulk_duration_in_second(self) -> float:
        return self._bbulk_duration / 1_000_000.0

    def get_b_avg_bytes_per_bulk(self) -> int:
        if self._bbulk_state_count == 0:
            return 0
        return int(self._bbulk_size_total / self._bbulk_state_count)

    def get_b_avg_packets_per_bulk(self) -> int:
        if self._bbulk_state_count == 0:
            return 0
        return int(self._bbulk_packet_count / self._bbulk_state_count)

    def get_b_avg_bulk_rate(self) -> int:
        if self._bbulk_duration == 0:
            return 0
        return int(self._bbulk_size_total / self.get_bbulk_duration_in_second())

    # Dumps -------------------------------------------------------------
    def get_label(self) -> str:
        return "NeedManualLabel"

    def dump_flow_based_features_ex(self) -> str:
        parts: List[str] = []
        add = parts.append

        add(self.flow_id or "")
        add(format_ip(self.src))
        add(str(self.src_port))
        add(format_ip(self.dst))
        add(str(self.dst_port))
        add(str(self.protocol))

        start_time = convert_milliseconds_to_string(self.flow_start_time // 1000, "%d/%m/%Y %I:%M:%S %p")
        add(start_time)

        flow_duration = self.flow_last_seen - self.flow_start_time
        add(str(flow_duration))

        add(str(self.fwd_pkt_stats.getN()))
        add(str(self.bwd_pkt_stats.getN()))
        add(str(self.fwd_pkt_stats.getSum()))
        add(str(self.bwd_pkt_stats.getSum()))

        for stats in (self.fwd_pkt_stats, self.bwd_pkt_stats):
            if stats.getN() > 0:
                add(str(stats.getMax()))
                add(str(stats.getMin()))
                add(str(stats.getMean()))
                add(str(stats.getStandardDeviation()))
            else:
                add("0")
                add("0")
                add("0")
                add("0")

        add(str(self.get_flow_bytes_per_sec()))
        add(str(self.get_flow_packets_per_sec()))
        add(str(self.flow_iat.getMean()))
        add(str(self.flow_iat.getStandardDeviation()))
        add(str(self.flow_iat.getMax()))
        add(str(self.flow_iat.getMin()))

        if len(self.forward) > 1:
            add(str(self.forward_iat.getSum()))
            add(str(self.forward_iat.getMean()))
            add(str(self.forward_iat.getStandardDeviation()))
            add(str(self.forward_iat.getMax()))
            add(str(self.forward_iat.getMin()))
        else:
            add("0")
            add("0")
            add("0")
            add("0")
            add("0")

        if len(self.backward) > 1:
            add(str(self.backward_iat.getSum()))
            add(str(self.backward_iat.getMean()))
            add(str(self.backward_iat.getStandardDeviation()))
            add(str(self.backward_iat.getMax()))
            add(str(self.backward_iat.getMin()))
        else:
            add("0")
            add("0")
            add("0")
            add("0")
            add("0")

        add(str(self.fpsh_cnt))
        add(str(self.bpsh_cnt))
        add(str(self.furg_cnt))
        add(str(self.burg_cnt))
        add(str(self.f_header_bytes))
        add(str(self.b_header_bytes))
        add(str(self.get_fpkts_per_second()))
        add(str(self.get_bpkts_per_second()))

        if self.forward or self.backward:
            add(str(self.flow_length_stats.getMin()))
            add(str(self.flow_length_stats.getMax()))
            add(str(self.flow_length_stats.getMean()))
            add(str(self.flow_length_stats.getStandardDeviation()))
            add(str(self.flow_length_stats.getVariance()))
        else:
            add("0")
            add("0")
            add("0")
            add("0")
            add("0")

        for key in ("FIN", "SYN", "RST", "PSH", "ACK", "URG", "CWR", "ECE"):
            add(str(self.flag_counts[key].value))

        add(str(self.get_down_up_ratio()))
        add(str(self.get_avg_packet_size()))
        add(str(self.f_avg_segment_size()))
        add(str(self.b_avg_segment_size()))
        add(str(self.get_f_avg_bytes_per_bulk()))
        add(str(self.get_f_avg_packets_per_bulk()))
        add(str(self.get_f_avg_bulk_rate()))
        add(str(self.get_b_avg_bytes_per_bulk()))
        add(str(self.get_b_avg_packets_per_bulk()))
        add(str(self.get_b_avg_bulk_rate()))

        add(str(self.get_sflow_fpackets()))
        add(str(self.get_sflow_fbytes()))
        add(str(self.get_sflow_bpackets()))
        add(str(self.get_sflow_bbytes()))

        add(str(self.init_win_bytes_forward))
        add(str(self.init_win_bytes_backward))
        add(str(self.act_data_pkt_forward))
        add(str(self.get_min_seg_size_forward()))

        if self.flow_active.getN() > 0:
            add(str(self.flow_active.getMean()))
            add(str(self.flow_active.getStandardDeviation()))
            add(str(self.flow_active.getMax()))
            add(str(self.flow_active.getMin()))
        else:
            add("0")
            add("0")
            add("0")
            add("0")

        if self.flow_idle.getN() > 0:
            add(str(self.flow_idle.getMean()))
            add(str(self.flow_idle.getStandardDeviation()))
            add(str(self.flow_idle.getMax()))
            add(str(self.flow_idle.getMin()))
        else:
            add("0")
            add("0")
            add("0")
            add("0")

        add(self.get_label())
        return self.separator.join(parts)

    # Helper rates -------------------------------------------------------
    def get_fpkts_per_second(self) -> float:
        duration = self.flow_last_seen - self.flow_start_time
        if duration <= 0:
            return 0.0
        return len(self.forward) / (duration / 1_000_000.0)

    def get_bpkts_per_second(self) -> float:
        duration = self.flow_last_seen - self.flow_start_time
        if duration <= 0:
            return 0.0
        return len(self.backward) / (duration / 1_000_000.0)


__all__ = ["BasicFlow"]
