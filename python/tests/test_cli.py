from __future__ import annotations

import socket

import dpkt

from cicflowmeter.cli import main
from cicflowmeter.flow_feature import FlowFeature


def _build_cli_sample_pcap(path) -> None:
    with path.open("wb") as fh:
        writer = dpkt.pcap.Writer(fh)

        src = socket.inet_aton("192.0.2.10")
        dst = socket.inet_aton("192.0.2.20")

        syn = dpkt.tcp.TCP(
            sport=44321,
            dport=80,
            seq=1,
            flags=dpkt.tcp.TH_SYN,
            win=64240,
        )
        ip_syn = dpkt.ip.IP(src=src, dst=dst, p=dpkt.ip.IP_PROTO_TCP, ttl=64)
        ip_syn.data = syn
        eth_syn = dpkt.ethernet.Ethernet(
            src=b"\xaa\xbb\xcc\xdd\xee\xff",
            dst=b"\x11\x22\x33\x44\x55\x66",
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=ip_syn,
        )
        writer.writepkt(bytes(eth_syn), ts=1.0)

        syn_ack = dpkt.tcp.TCP(
            sport=80,
            dport=44321,
            seq=100,
            ack=2,
            flags=dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK,
            win=65535,
        )
        ip_syn_ack = dpkt.ip.IP(src=dst, dst=src, p=dpkt.ip.IP_PROTO_TCP, ttl=64)
        ip_syn_ack.data = syn_ack
        eth_syn_ack = dpkt.ethernet.Ethernet(
            src=b"\x11\x22\x33\x44\x55\x66",
            dst=b"\xaa\xbb\xcc\xdd\xee\xff",
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=ip_syn_ack,
        )
        writer.writepkt(bytes(eth_syn_ack), ts=1.001)

        ack = dpkt.tcp.TCP(
            sport=44321,
            dport=80,
            seq=2,
            ack=101,
            flags=dpkt.tcp.TH_ACK,
            win=64000,
        )
        ip_ack = dpkt.ip.IP(src=src, dst=dst, p=dpkt.ip.IP_PROTO_TCP, ttl=64)
        ip_ack.data = ack
        eth_ack = dpkt.ethernet.Ethernet(
            src=b"\xaa\xbb\xcc\xdd\xee\xff",
            dst=b"\x11\x22\x33\x44\x55\x66",
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=ip_ack,
        )
        writer.writepkt(bytes(eth_ack), ts=1.002)


def test_cli_generates_flow_csv(tmp_path):
    pcap_path = tmp_path / "handshake.pcap"
    _build_cli_sample_pcap(pcap_path)

    output_dir = tmp_path / "out"
    exit_code = main([str(pcap_path), str(output_dir), "--log-level", "ERROR"])

    assert exit_code == 0

    output_file = output_dir / f"{pcap_path.name}_Flow.csv"
    assert output_file.exists()

    lines = [line for line in output_file.read_text().splitlines() if line.strip()]
    assert len(lines) >= 2
    assert lines[0] == FlowFeature.get_header()
    assert lines[1].endswith("NeedManualLabel")
