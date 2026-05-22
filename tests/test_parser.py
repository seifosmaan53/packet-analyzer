from __future__ import annotations

from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest

from src.parser import parse


def test_parse_uses_packet_timestamp_when_available() -> None:
    raw = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=443, flags="S")
    raw.time = 1234.5

    parsed = parse(raw)

    assert parsed is not None
    assert parsed.ts == 1234.5


def test_parse_recognizes_icmpv6_echo_packets() -> None:
    raw = IPv6(src="2001:db8::1", dst="2001:db8::2") / ICMPv6EchoRequest()

    parsed = parse(raw)

    assert parsed is not None
    assert parsed.proto == "ICMPv6"
    assert parsed.src == "2001:db8::1"
    assert parsed.dst == "2001:db8::2"
