"""Python port of cic.cs.unb.ca.jnetpcap.FlowGenerator."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, List, Optional

from .basic_flow import BasicFlow
from .basic_packet_info import BasicPacketInfo
from .listeners import FlowGenListener
from .utils import LINE_SEP

logger = logging.getLogger(__name__)


class FlowGenerator:
    def __init__(self, bidirectional: bool, flow_timeout: int, activity_timeout: int) -> None:
        self.bidirectional = bidirectional
        self.flow_timeout = flow_timeout
        self.flow_activity_timeout = activity_timeout
        self._listener: Optional[FlowGenListener] = None
        self._init_state()

    # ------------------------------------------------------------------
    def _init_state(self) -> None:
        self.current_flows: Dict[str, BasicFlow] = {}
        self.finished_flows: Dict[int, BasicFlow] = {}
        self.ip_addresses: Dict[str, List[str]] = {}
        self.finished_flow_count = 0

    def add_flow_listener(self, listener: FlowGenListener) -> None:
        self._listener = listener

    # ------------------------------------------------------------------
    def add_packet(self, packet: Optional[BasicPacketInfo]) -> None:
        if packet is None:
            return

        current_timestamp = packet.timestamp
        fwd_id = packet.fwd_flow_id()
        bwd_id = packet.bwd_flow_id()

        flow_id: Optional[str] = None
        if fwd_id in self.current_flows:
            flow_id = fwd_id
        elif bwd_id in self.current_flows:
            flow_id = bwd_id

        if flow_id is not None:
            packet.set_flow_id(flow_id)
            flow = self.current_flows[flow_id]

            if (current_timestamp - flow.get_flow_start_time()) > self.flow_timeout:
                self._close_flow(flow_id, flow, packet, timed_out=True)
                return

            if packet.flag_fin:
                self._handle_fin_packet(flow_id, flow, packet, current_timestamp)
                return

            if packet.flag_rst:
                logger.debug("FlagRST current has %d flow", len(self.current_flows))
                flow.add_packet(packet)
                self._emit_or_store(flow)
                self.current_flows.pop(flow_id, None)
                return

            if flow.get_fwd_fin_flags() == 0 or flow.get_bwd_fin_flags() == 0:
                flow.update_active_idle_time(current_timestamp, self.flow_activity_timeout)
                flow.add_packet(packet)
                self.current_flows[flow_id] = flow
            else:
                logger.warning(
                    "FLOW already closed! fwdFIN %s bwdFIN %s",
                    flow.get_fwd_fin_flags(),
                    flow.get_bwd_fin_flags(),
                )
        else:
            packet.set_flow_id(fwd_id)
            self.current_flows[fwd_id] = BasicFlow(
                self.bidirectional,
                packet,
                self.flow_activity_timeout,
            )

    # ------------------------------------------------------------------
    def _close_flow(
        self,
        flow_id: str,
        flow: BasicFlow,
        packet: BasicPacketInfo,
        timed_out: bool = False,
    ) -> None:
        if flow.packet_count() > 1:
            if self._listener:
                self._listener.on_flow_generated(flow)
            else:
                self.finished_flows[self._next_flow_index()] = flow
        self.current_flows.pop(flow_id, None)

        new_flow = BasicFlow(
            self.bidirectional,
            packet,
            self.flow_activity_timeout,
            flow_src=flow.get_src(),
            flow_dst=flow.get_dst(),
            flow_src_port=flow.get_src_port(),
            flow_dst_port=flow.get_dst_port(),
        )
        self.current_flows[flow_id] = new_flow

        if timed_out and len(self.current_flows) % 50 == 0:
            logger.debug("Timeout current has %d flow", len(self.current_flows))

    def _handle_fin_packet(
        self,
        flow_id: str,
        flow: BasicFlow,
        packet: BasicPacketInfo,
        current_timestamp: int,
    ) -> None:
        if packet.src == flow.get_src():
            if flow.set_fwd_fin_flags() == 1:
                if (flow.get_fwd_fin_flags() + flow.get_bwd_fin_flags()) == 2:
                    logger.debug("FlagFIN current has %d flow", len(self.current_flows))
                    flow.add_packet(packet)
                    self._emit_or_store(flow)
                    self.current_flows.pop(flow_id, None)
                else:
                    logger.info("Forward flow closed due to FIN Flag")
                    flow.update_active_idle_time(current_timestamp, self.flow_activity_timeout)
                    flow.add_packet(packet)
                    self.current_flows[flow_id] = flow
            else:
                logger.warning(
                    "Forward flow received %s FIN packets", flow.get_fwd_fin_flags()
                )
        else:
            if flow.set_bwd_fin_flags() == 1:
                if (flow.get_fwd_fin_flags() + flow.get_bwd_fin_flags()) == 2:
                    logger.debug("FlagFIN current has %d flow", len(self.current_flows))
                    flow.add_packet(packet)
                    self._emit_or_store(flow)
                    self.current_flows.pop(flow_id, None)
                else:
                    logger.info("Backwards flow closed due to FIN Flag")
                    flow.update_active_idle_time(current_timestamp, self.flow_activity_timeout)
                    flow.add_packet(packet)
                    self.current_flows[flow_id] = flow
            else:
                logger.warning(
                    "Backward flow received %s FIN packets", flow.get_bwd_fin_flags()
                )

    def _emit_or_store(self, flow: BasicFlow) -> None:
        if self._listener:
            self._listener.on_flow_generated(flow)
        else:
            self.finished_flows[self._next_flow_index()] = flow

    # ------------------------------------------------------------------
    def dump_labeled_flow_based_features(self, path: str, filename: str, header: str) -> int:
        file_path = Path(path) / filename
        total = 0
        zero_pkt = 0

        with file_path.open("w", encoding="utf-8") as output:
            output.write(header + LINE_SEP)
            for flow in self.finished_flows.values():
                if flow.packet_count() > 1:
                    output.write(flow.dump_flow_based_features_ex() + LINE_SEP)
                    total += 1
                else:
                    zero_pkt += 1
            logger.debug("dumpLabeledFlow finishedFlows -> %s,%s", zero_pkt, total)

            output.write(header + LINE_SEP)
            for flow in self.current_flows.values():
                if flow.packet_count() > 1:
                    output.write(flow.dump_flow_based_features_ex() + LINE_SEP)
                    total += 1
                else:
                    zero_pkt += 1
            logger.debug("dumpLabeledFlow total(include current) -> %s,%s", zero_pkt, total)

        return total

    def dump_labeled_current_flow(self, file_full_path: str, header: str) -> int:
        if not file_full_path or header is None:
            raise ValueError("file_full_path and header must be provided")

        file_path = Path(file_full_path)
        total = 0

        if file_path.exists():
            mode = "a"
        else:
            mode = "w"

        with file_path.open(mode, encoding="utf-8") as output:
            if mode == "w":
                output.write(header + LINE_SEP)
            for flow in self.current_flows.values():
                if flow.packet_count() > 1:
                    output.write(flow.dump_flow_based_features_ex() + LINE_SEP)
                    total += 1
        return total

    # ------------------------------------------------------------------
    def _next_flow_index(self) -> int:
        self.finished_flow_count += 1
        return self.finished_flow_count
