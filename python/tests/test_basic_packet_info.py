import unittest

from cicflowmeter import BasicPacketInfo, IdGenerator


class BasicPacketInfoTest(unittest.TestCase):
    def test_flow_id_generation_forward_vs_backward(self) -> None:
        generator = IdGenerator()
        src = bytes([10, 0, 0, 2])
        dst = bytes([10, 0, 0, 1])
        pkt = BasicPacketInfo(
            src=src,
            dst=dst,
            src_port=1234,
            dst_port=80,
            protocol=6,
            timestamp=1_000,
            generator=generator,
        )

        forward_id = pkt.fwd_flow_id()
        backward_id = pkt.bwd_flow_id()

        self.assertNotEqual(forward_id, backward_id)
        self.assertTrue(forward_id.endswith("1234-80-6"))
        self.assertTrue(backward_id.endswith("80-1234-6"))

    def test_payload_packet_counter_increments(self) -> None:
        generator = IdGenerator()
        pkt = BasicPacketInfo(
            src=bytes([192, 168, 0, 1]),
            dst=bytes([192, 168, 0, 2]),
            src_port=1111,
            dst_port=2222,
            protocol=17,
            timestamp=0,
            generator=generator,
        )

        self.assertEqual(pkt.get_payload_packet(), 1)
        self.assertEqual(pkt.get_payload_packet(), 2)


if __name__ == "__main__":  # pragma: no cover - convenience
    unittest.main()
