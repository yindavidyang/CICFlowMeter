import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from cicflowmeter import BasicPacketInfo, FlowGenerator, IdGenerator


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
    pkt.flag_fin = fin
    return pkt


class FlowGeneratorTest(unittest.TestCase):
    def test_timeout_moves_flow_to_finished_collection(self) -> None:
        generator = FlowGenerator(bidirectional=True, flow_timeout=500_000, activity_timeout=200_000)
        id_gen = IdGenerator()
        src = bytes([192, 0, 2, 1])
        dst = bytes([192, 0, 2, 2])

        pkt1 = _packet(id_gen, src, dst, 4000, 80, 6, timestamp=0, payload=100, header=40)
        generator.add_packet(pkt1)

        pkt2 = _packet(id_gen, src, dst, 4000, 80, 6, timestamp=200_000, payload=50, header=40)
        generator.add_packet(pkt2)

        pkt3 = _packet(id_gen, src, dst, 4000, 80, 6, timestamp=800_000, payload=25, header=40)
        generator.add_packet(pkt3)

        self.assertEqual(len(generator.finished_flows), 1)
        self.assertEqual(len(generator.current_flows), 1)

    def test_dump_labeled_flow_writes_file(self) -> None:
        generator = FlowGenerator(bidirectional=True, flow_timeout=500_000, activity_timeout=200_000)
        id_gen = IdGenerator()
        src = bytes([10, 0, 0, 10])
        dst = bytes([10, 0, 0, 20])

        pkt1 = _packet(id_gen, src, dst, 1234, 80, 6, timestamp=0, payload=120, header=40)
        pkt2 = _packet(id_gen, src, dst, 1234, 80, 6, timestamp=100_000, payload=60, header=40)
        generator.add_packet(pkt1)
        generator.add_packet(pkt2)

        with TemporaryDirectory() as tmpdir:
            outfile = "flows_test.csv"
            header = "col"
            total = generator.dump_labeled_flow_based_features(tmpdir, outfile, header)

            self.assertGreaterEqual(total, 1)
            file_path = Path(tmpdir) / outfile
            self.assertTrue(file_path.exists())

    def test_fin_packets_close_flow(self) -> None:
        generator = FlowGenerator(bidirectional=True, flow_timeout=1_000_000, activity_timeout=500_000)
        id_gen = IdGenerator()
        src = bytes([10, 1, 0, 5])
        dst = bytes([10, 1, 0, 6])

        forward1 = _packet(id_gen, src, dst, 5000, 443, 6, timestamp=100_000, payload=200, header=40)
        generator.add_packet(forward1)

        backward1 = _packet(id_gen, dst, src, 443, 5000, 6, timestamp=200_000, payload=150, header=40)
        generator.add_packet(backward1)

        forward_fin = _packet(id_gen, src, dst, 5000, 443, 6, timestamp=250_000, payload=0, header=40, fin=True)
        generator.add_packet(forward_fin)

        backward_fin = _packet(id_gen, dst, src, 443, 5000, 6, timestamp=300_000, payload=0, header=40, fin=True)
        generator.add_packet(backward_fin)

        self.assertEqual(len(generator.finished_flows), 1)
        self.assertEqual(len(generator.current_flows), 0)


if __name__ == "__main__":  # pragma: no cover - convenience
    unittest.main()
