import pytest

from cicflowmeter.live_capture import LiveCapture


@pytest.fixture
def scapy_layers():
    scapy = pytest.importorskip("scapy.all")
    from scapy.all import Ether, IP, IPv6, TCP, UDP, Raw

    return {
        "Ether": Ether,
        "IP": IP,
        "IPv6": IPv6,
        "TCP": TCP,
        "UDP": UDP,
        "Raw": Raw,
    }


def test_build_packet_info_tcp_ipv4(scapy_layers):
    capture = LiveCapture("lo")

    packet = (
        scapy_layers["Ether"]()
        / scapy_layers["IP"](src="10.0.0.1", dst="10.0.0.2", proto=6)
        / scapy_layers["TCP"](sport=1234, dport=80, flags="S", window=2048)
        / scapy_layers["Raw"](load=b"hello")
    )
    packet.time = 1.5

    packet_info = capture._build_packet_info(packet)
    assert packet_info is not None
    assert packet_info.src_port == 1234
    assert packet_info.dst_port == 80
    assert packet_info.protocol == 6
    assert packet_info.timestamp == 1_500_000
    assert packet_info.payload_bytes == len(b"hello")
    # TCP header should include options + base header (20 bytes without options)
    assert packet_info.header_bytes >= 20
    assert packet_info.has_flag_syn()
    assert not packet_info.has_flag_ack()


def test_build_packet_info_udp_ipv6(scapy_layers):
    capture = LiveCapture("lo", read_ip4=False, read_ip6=True)

    packet = (
        scapy_layers["Ether"]()
        / scapy_layers["IPv6"](src="2001:db8::1", dst="2001:db8::2", nh=17)
        / scapy_layers["UDP"](sport=5353, dport=53)
        / scapy_layers["Raw"](load=b"abc")
    )
    packet.time = 2.0

    packet_info = capture._build_packet_info(packet)
    assert packet_info is not None
    assert packet_info.protocol == 17
    assert packet_info.timestamp == 2_000_000
    assert packet_info.payload_bytes == 3
    assert packet_info.header_bytes >= 8
