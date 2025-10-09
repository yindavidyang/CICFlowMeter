from __future__ import annotations

import socket
from types import SimpleNamespace

import dpkt

from cicflowmeter.pcap_compat import get_hardware_address, list_devices, open_live, open_offline


def test_open_live_configures_capture():
    capture = open_live(
        "eth0",
        snaplen=1_024,
        promisc=False,
        timeout_ms=250,
        bidirectional=False,
        read_ip6=True,
    )

    assert capture.interface == "eth0"
    assert capture.snaplen == 1_024
    assert capture.promiscuous is False
    assert capture.read_timeout_ms == 250
    assert capture.flow_generator.bidirectional is False
    assert capture.read_ip6 is True


def test_open_offline_returns_packet_reader(tmp_path):
    path = tmp_path / "sample.pcap"
    with path.open("wb") as fh:
        writer = dpkt.pcap.Writer(fh)
        tcp = dpkt.tcp.TCP(sport=1234, dport=80, flags=dpkt.tcp.TH_SYN)
        tcp.win = 8192
        ip = dpkt.ip.IP(
            src=socket.inet_aton("10.0.0.1"),
            dst=socket.inet_aton("10.0.0.2"),
            p=dpkt.ip.IP_PROTO_TCP,
            ttl=64,
            len=20 + len(tcp),
            id=1,
        )
        ip.v = 4
        ip.hl = 5
        ip.data = tcp
        ethernet = dpkt.ethernet.Ethernet(
            dst=b"\xaa\xbb\xcc\xdd\xee\xff",
            src=b"\x11\x22\x33\x44\x55\x66",
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=ip,
        )
        writer.writepkt(bytes(ethernet))

    reader = open_offline(str(path))
    try:
        packet = reader.next_packet()
        assert packet is not None
        assert packet.protocol == dpkt.ip.IP_PROTO_TCP
    finally:
        reader.close()


def test_list_devices_with_psutil(monkeypatch):
    import cicflowmeter.pcap_compat as compat

    psutil_stub = SimpleNamespace(
        AF_LINK=17,
        net_if_addrs=lambda: {
            "eth0": [
                SimpleNamespace(
                    family=socket.AF_INET,
                    address="192.168.1.10",
                    netmask="255.255.255.0",
                    broadcast="192.168.1.255",
                ),
                SimpleNamespace(
                    family=17,
                    address="11:22:33:44:55:66",
                    netmask=None,
                    broadcast=None,
                ),
            ],
            "lo": [
                SimpleNamespace(
                    family=socket.AF_INET,
                    address="127.0.0.1",
                    netmask="255.0.0.0",
                    broadcast=None,
                )
            ],
        },
    )

    monkeypatch.setattr(compat, "psutil", psutil_stub)
    devices = list_devices()
    names = [dev.name for dev in devices]
    assert "eth0" in names
    eth0 = next(dev for dev in devices if dev.name == "eth0")
    assert any(
        addr.address == "192.168.1.10" and addr.netmask == "255.255.255.0"
        for addr in eth0.addresses
    )
    assert eth0.hardware_address == "11:22:33:44:55:66"
    loop = next(dev for dev in devices if dev.name == "lo")
    assert loop.is_loopback


def test_get_hardware_address(monkeypatch):
    import cicflowmeter.pcap_compat as compat

    psutil_stub = SimpleNamespace(
        AF_LINK=17,
        net_if_addrs=lambda: {
            "eth0": [
                SimpleNamespace(family=17, address="00:11:22:33:44:55"),
            ]
        },
    )
    monkeypatch.setattr(compat, "psutil", psutil_stub)
    assert get_hardware_address("eth0") == "00:11:22:33:44:55"
    assert get_hardware_address("does-not-exist") is None
