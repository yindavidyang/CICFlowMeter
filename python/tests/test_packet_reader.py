from __future__ import annotations

import socket

import dpkt

from cicflowmeter.packet_reader import PacketReader


def _build_sample_pcap(path) -> None:
    with path.open("wb") as fh:
        writer = dpkt.pcap.Writer(fh)

        tcp_payload = b"hello"
        tcp = dpkt.tcp.TCP(
            sport=12345,
            dport=80,
            seq=1,
            flags=dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK,
            win=512,
        )
        tcp.data = tcp_payload

        ip = dpkt.ip.IP(
            src=socket.inet_aton("192.0.2.1"),
            dst=socket.inet_aton("192.0.2.2"),
            p=dpkt.ip.IP_PROTO_TCP,
            ttl=64,
        )
        ip.data = tcp

        ethernet = dpkt.ethernet.Ethernet(
            src=b"\xaa\xaa\xaa\xaa\xaa\xaa",
            dst=b"\xbb\xbb\xbb\xbb\xbb\xbb",
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=ip,
        )
        writer.writepkt(bytes(ethernet), ts=1.0)

        udp_payload = b"payload"
        udp = dpkt.udp.UDP(sport=53, dport=4444)
        udp.data = udp_payload
        udp.pack()

        ip6 = dpkt.ip6.IP6(
            src=socket.inet_pton(socket.AF_INET6, "2001:db8::1"),
            dst=socket.inet_pton(socket.AF_INET6, "2001:db8::2"),
            nxt=dpkt.ip.IP_PROTO_UDP,
            hlim=64,
        )
        ip6.data = udp

        ethernet6 = dpkt.ethernet.Ethernet(
            src=b"\xcc\xcc\xcc\xcc\xcc\xcc",
            dst=b"\xdd\xdd\xdd\xdd\xdd\xdd",
            type=dpkt.ethernet.ETH_TYPE_IP6,
            data=ip6,
        )
        writer.writepkt(bytes(ethernet6), ts=2.5)

        writer.close()


def test_packet_reader_iterates_over_tcp_and_udp_packets(tmp_path):
    pcap_path = tmp_path / "sample.pcap"
    _build_sample_pcap(pcap_path)

    reader = PacketReader(pcap_path, read_ip4=True, read_ip6=True)
    packets = list(reader)

    assert len(packets) == 2
    first, second = packets

    assert first.protocol == dpkt.ip.IP_PROTO_TCP
    assert first.src_port == 12345
    assert first.dst_port == 80
    assert first.payload_bytes == len(b"hello")
    assert first.header_bytes == 20
    assert first.tcp_window == 512
    assert first.flag_syn and first.flag_ack
    assert not first.flag_fin and not first.flag_rst

    assert second.protocol == dpkt.ip.IP_PROTO_UDP
    assert second.src_port == 53
    assert second.dst_port == 4444
    assert second.payload_bytes == len(b"payload")
    assert second.header_bytes == 8

    assert reader.first_packet_timestamp == 1_000_000
    assert reader.last_packet_timestamp == 2_500_000


def test_next_packet_iteration(tmp_path):
    pcap_path = tmp_path / "sample_next.pcap"
    _build_sample_pcap(pcap_path)

    reader = PacketReader(pcap_path, read_ip4=True, read_ip6=True)

    first = reader.next_packet()
    second = reader.next_packet()
    third = reader.next_packet()

    assert first is not None
    assert second is not None
    assert third is None

    reader.close()
