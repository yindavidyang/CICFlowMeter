import unittest

from cicflowmeter import BasicFlow, BasicPacketInfo, IdGenerator


def _packet(
    generator: IdGenerator,
    src: bytes,
    dst: bytes,
    src_port: int,
    dst_port: int,
    protocol: int,
    timestamp: int,
    payload: int,
    header: int,
    *,
    fin: bool = False,
    psh: bool = False,
    urg: bool = False,
    window: int = 0,
) -> BasicPacketInfo:
    pkt = BasicPacketInfo(
        src=src,
        dst=dst,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        timestamp=timestamp,
        generator=generator,
    )
    pkt.payload_bytes = payload
    pkt.header_bytes = header
    pkt.tcp_window = window
    pkt.flag_fin = fin
    pkt.flag_psh = psh
    pkt.flag_urg = urg
    return pkt


class BasicFlowTest(unittest.TestCase):
    def test_basic_flow_collects_forward_and_backward_statistics(self) -> None:
        generator = IdGenerator()
        src = bytes([192, 168, 0, 10])
        dst = bytes([192, 168, 0, 20])

        first_packet = _packet(
            generator,
            src,
            dst,
            5555,
            443,
            6,
            timestamp=1_000_000,
            payload=500,
            header=60,
            psh=True,
            window=1024,
        )

        flow = BasicFlow(True, first_packet, activity_timeout=1_000_000)

        second_packet = _packet(
            generator,
            src,
            dst,
            5555,
            443,
            6,
            timestamp=1_500_000,
            payload=250,
            header=60,
        )
        flow.add_packet(second_packet)

        backward_packet = _packet(
            generator,
            dst,
            src,
            443,
            5555,
            6,
            timestamp=1_800_000,
            payload=300,
            header=60,
            urg=True,
        )
        flow.add_packet(backward_packet)

        self.assertEqual(flow.get_total_fwd_packets(), 2)
        self.assertEqual(flow.get_total_backward_packets(), 1)
        self.assertEqual(flow.get_flow_duration(), 800_000)
        self.assertEqual(flow.get_fwd_psh_flags(), 1)
        self.assertEqual(flow.get_flag_count("URG"), 1)
        self.assertGreater(flow.get_flow_packets_per_sec(), 0)

    def test_min_segment_size_defaults_to_zero_when_no_forward_packets(self) -> None:
        generator = IdGenerator()
        src = bytes([1, 1, 1, 1])
        dst = bytes([2, 2, 2, 2])

        pkt = _packet(
            generator,
            src,
            dst,
            1234,
            80,
            6,
            timestamp=100,
            payload=0,
            header=0,
        )
        flow = BasicFlow(False, pkt, activity_timeout=1_000_000)
        self.assertEqual(flow.get_min_seg_size_forward(), 0.0)


if __name__ == "__main__":  # pragma: no cover - convenience
    unittest.main()
