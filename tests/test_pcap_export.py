"""Tests for saving captures to .pcap (Wireshark/tshark interop).

These build raw Scapy packets directly, so they exercise the real write/read
path without needing a live sniffer or sudo.
"""
from __future__ import annotations

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import PcapReader

from src.capture import Capture, write_pcap
from src.parser import parse


def _sample_packets() -> list:
    # Consistent Ethernet framing with explicit MACs: a single-interface capture
    # never mixes linktypes, and explicit MACs avoid ARP resolution (needs root).
    eth = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
    return [
        eth / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, flags="S"),
        eth
        / IP(src="10.0.0.2", dst="10.0.0.53")
        / UDP(sport=5353, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com")),
        eth / IP(src="10.0.0.9", dst="10.0.0.1") / TCP(dport=443, flags="SA"),
    ]


def test_write_pcap_roundtrips_through_scapy(tmp_path) -> None:
    out = tmp_path / "nested" / "capture.pcap"  # also checks parent dir creation
    packets = _sample_packets()

    count = write_pcap(packets, out)

    assert count == len(packets)
    assert out.exists()

    with PcapReader(str(out)) as reader:
        read_back = list(reader)
    assert len(read_back) == len(packets)
    # The bytes survived the round-trip, so our parser still recognizes them.
    parsed = [parse(pkt) for pkt in read_back]
    assert parsed[0] is not None and parsed[0].proto == "TCP"
    assert parsed[1] is not None and parsed[1].dns_query == "example.com"


def test_write_pcap_empty_produces_valid_file(tmp_path) -> None:
    out = tmp_path / "empty.pcap"

    assert write_pcap([], out) == 0
    assert out.exists()
    with PcapReader(str(out)) as reader:
        assert list(reader) == []


def test_capture_buffers_raw_packets_and_writes_pcap(tmp_path) -> None:
    capture = Capture()
    for pkt in _sample_packets():
        capture._on_packet(pkt)  # what the sniffer thread calls per frame

    assert len(capture.raw_buffer) == 3

    out = tmp_path / "from_buffer.pcap"
    assert capture.write_pcap(out) == 3
    with PcapReader(str(out)) as reader:
        assert len(list(reader)) == 3


def test_capture_raw_buffer_is_bounded() -> None:
    capture = Capture(pcap_buffer=2)
    for pkt in _sample_packets():  # feed 3 into a size-2 buffer
        capture._on_packet(pkt)

    # Oldest packet is evicted; only the most recent two are retained.
    assert len(capture.raw_buffer) == 2
