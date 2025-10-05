import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from cicflowmeter import (
    BasicPacketInfo,
    FlowGenerator,
    IdGenerator,
    IncrementalCSVWriter,
)


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


class AncillaryUtilitiesTest(unittest.TestCase):
    def test_incremental_csv_writer_writes_header_once(self) -> None:
        with TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "flows.csv"
            writer = IncrementalCSVWriter(target, "col")
            writer.append_rows(["row1"])
            writer.append_rows(["row2"])  # header should not repeat

            content = target.read_text().splitlines()
            self.assertEqual(content, ["col", "row1", "row2"])

    def test_flow_generator_ip_summary_and_exports(self) -> None:
        generator = FlowGenerator(bidirectional=True, flow_timeout=500_000, activity_timeout=200_000)
        id_gen = IdGenerator()

        ip1 = bytes([192, 0, 2, 1])
        ip2 = bytes([192, 0, 2, 2])
        ip3 = bytes([192, 0, 2, 3])

        generator.add_packet(_packet(id_gen, ip1, ip2, 4000, 80, 6, 0, 100, 40))
        generator.add_packet(_packet(id_gen, ip2, ip1, 80, 4000, 6, 50_000, 80, 40))
        generator.add_packet(_packet(id_gen, ip1, ip2, 4000, 80, 6, 100_000, 0, 40, fin=True))
        generator.add_packet(_packet(id_gen, ip2, ip1, 80, 4000, 6, 150_000, 0, 40, fin=True))

        generator.add_packet(_packet(id_gen, ip3, ip1, 5000, 443, 6, 1_200_000, 200, 40))
        generator.add_packet(_packet(id_gen, ip1, ip3, 443, 5000, 6, 1_250_000, 150, 40))
        generator.add_packet(_packet(id_gen, ip3, ip1, 5000, 443, 6, 1_300_000, 0, 40, fin=True))
        generator.add_packet(_packet(id_gen, ip1, ip3, 443, 5000, 6, 1_350_000, 0, 40, fin=True))

        summary = generator.summarize_ip_addresses()
        self.assertIn("192.0.2.1", summary)
        ip1_summary = summary["192.0.2.1"]
        self.assertEqual(ip1_summary.flows_as_src, 1)
        self.assertEqual(ip1_summary.flows_as_dst, 1)
        self.assertEqual(ip1_summary.packets_sent, 4)
        self.assertEqual(ip1_summary.packets_received, 4)
        self.assertEqual(int(ip1_summary.bytes_sent), 250)
        self.assertEqual(int(ip1_summary.bytes_received), 280)

        buckets = generator.summarize_time_buckets(1.0)
        self.assertEqual(len(buckets), 2)
        self.assertEqual(buckets[0].flow_count, 1)
        self.assertEqual(int(buckets[0].byte_count), 180)
        self.assertEqual(int(buckets[1].byte_count), 350)

        with TemporaryDirectory() as tmpdir:
            ip_csv = Path(tmpdir) / "ips.csv"
            count = generator.dump_ip_address_summary(str(ip_csv))
            self.assertEqual(count, len(summary))
            lines = ip_csv.read_text().splitlines()
            self.assertGreaterEqual(len(lines), 1)
            self.assertTrue(lines[0].startswith("ip,"))

            time_csv = Path(tmpdir) / "time.csv"
            bucket_count = generator.dump_time_buckets(str(time_csv), 1.0)
            self.assertEqual(bucket_count, len(buckets))
            time_lines = time_csv.read_text().splitlines()
            self.assertTrue(time_lines[0].startswith("start_us,"))


if __name__ == "__main__":  # pragma: no cover - convenience
    unittest.main()
