"""Flatten Scapy packets to a lightweight dataclass for downstream consumers."""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoReply, ICMPv6EchoRequest
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.packet import Packet


@dataclass(frozen=True)
class ParsedPacket:
    ts: float
    proto: str               # "TCP", "UDP", "ICMP", "OTHER"
    src: str
    dst: str
    sport: Optional[int] = None
    dport: Optional[int] = None
    length: int = 0
    tcp_flags: Optional[str] = None       # e.g. "S", "SA", "FA"
    dns_query: Optional[str] = None
    dns_qtype: Optional[int] = None       # 1=A, 16=TXT, 28=AAAA, ...
    dns_response_code: Optional[int] = None
    http_host: Optional[str] = None
    http_path: Optional[str] = None
    http_method: Optional[str] = None
    summary: str = ""

    def short(self) -> str:
        """One-line representation for the live feed."""
        base = f"{self.src:<15} > {self.dst:<15} {self.proto}"
        if self.sport is not None and self.dport is not None:
            base += f" {self.sport}->{self.dport}"
        if self.tcp_flags:
            base += f" [{self.tcp_flags}]"
        if self.dns_query:
            base += f" DNS? {self.dns_query}"
        if self.http_method:
            base += f" HTTP {self.http_method} {self.http_host or ''}{self.http_path or ''}"
        return base


def _first_dns_question(qd) -> Optional[DNSQR]:
    """Return the first DNS question record across Scapy's representations.

    A freshly-built `DNS(qd=DNSQR(...))` exposes `qd` as a single DNSQR, but a
    packet deserialized from the wire (or a .pcap) returns a list-like wrapper.
    Handle both so DNS queries are still extracted in offline analysis.
    """
    if qd is None:
        return None
    if isinstance(qd, DNSQR):
        return qd
    try:
        first = qd[0]
    except (TypeError, IndexError):
        return None
    return first if isinstance(first, DNSQR) else None


def _tcp_flag_str(flags: int) -> str:
    """Convert TCP flag bitfield to short string like 'SA' for SYN+ACK."""
    mapping = [
        (0x01, "F"),  # FIN
        (0x02, "S"),  # SYN
        (0x04, "R"),  # RST
        (0x08, "P"),  # PSH
        (0x10, "A"),  # ACK
        (0x20, "U"),  # URG
    ]
    return "".join(ch for bit, ch in mapping if flags & bit) or "."


def parse(pkt: Packet) -> Optional[ParsedPacket]:
    """Extract fields we care about. Returns None for non-IP traffic."""
    ts = float(getattr(pkt, "time", time.time()))
    length = len(pkt)

    if IP in pkt:
        ip = pkt[IP]
        src, dst = ip.src, ip.dst
    elif IPv6 in pkt:
        ip = pkt[IPv6]
        src, dst = ip.src, ip.dst
    else:
        return None

    proto = "OTHER"
    sport = dport = None
    tcp_flags = None
    dns_query = dns_qtype = dns_rcode = None
    http_host = http_path = http_method = None

    if TCP in pkt:
        proto = "TCP"
        tcp = pkt[TCP]
        sport, dport = int(tcp.sport), int(tcp.dport)
        tcp_flags = _tcp_flag_str(int(tcp.flags))

        if HTTPRequest in pkt:
            req = pkt[HTTPRequest]
            http_method = req.Method.decode(errors="ignore") if req.Method else None
            http_host = req.Host.decode(errors="ignore") if req.Host else None
            http_path = req.Path.decode(errors="ignore") if req.Path else None
        elif HTTPResponse in pkt:
            http_method = "RESP"

    elif UDP in pkt:
        proto = "UDP"
        udp = pkt[UDP]
        sport, dport = int(udp.sport), int(udp.dport)

        if DNS in pkt:
            dns = pkt[DNS]
            dns_rcode = int(dns.rcode) if dns.qr == 1 else None
            question = _first_dns_question(dns.qd)
            if question is not None:
                qname = question.qname
                if isinstance(qname, bytes):
                    qname = qname.decode(errors="ignore").rstrip(".")
                dns_query = qname
                dns_qtype = int(question.qtype)

    elif ICMP in pkt:
        proto = "ICMP"
    elif ICMPv6EchoRequest in pkt or ICMPv6EchoReply in pkt:
        proto = "ICMPv6"

    return ParsedPacket(
        ts=ts,
        proto=proto,
        src=src,
        dst=dst,
        sport=sport,
        dport=dport,
        length=length,
        tcp_flags=tcp_flags,
        dns_query=dns_query,
        dns_qtype=dns_qtype,
        dns_response_code=dns_rcode,
        http_host=http_host,
        http_path=http_path,
        http_method=http_method,
        summary=pkt.summary(),
    )
