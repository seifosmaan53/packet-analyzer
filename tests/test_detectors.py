"""Unit tests for the detectors. Synthetic ParsedPackets — no Scapy needed."""
from __future__ import annotations

import time

import pytest

from src.parser import ParsedPacket
from src.detectors import (
    DnsAnomalyDetector,
    PortScanDetector,
    StatsAnomalyDetector,
    SynFloodDetector,
)


def syn(src: str, dst: str = "10.0.0.1", dport: int = 80, ts: float | None = None) -> ParsedPacket:
    return ParsedPacket(
        ts=ts if ts is not None else time.time(),
        proto="TCP",
        src=src,
        dst=dst,
        sport=12345,
        dport=dport,
        length=60,
        tcp_flags="S",
    )


def dns_query(src: str, q: str, qtype: int = 1) -> ParsedPacket:
    return ParsedPacket(
        ts=time.time(),
        proto="UDP",
        src=src,
        dst="8.8.8.8",
        sport=33333,
        dport=53,
        length=80,
        dns_query=q,
        dns_qtype=qtype,
    )


def dns_response(dst: str, rcode: int = 3) -> ParsedPacket:
    return ParsedPacket(
        ts=time.time(),
        proto="UDP",
        src="8.8.8.8",
        dst=dst,
        sport=53,
        dport=33333,
        length=80,
        dns_response_code=rcode,
    )


class TestSynFloodDetector:
    def test_below_threshold_no_alert(self):
        det = SynFloodDetector(window_seconds=5.0, threshold=100)
        for _ in range(50):
            assert det.inspect(syn("10.0.0.42")) is None

    def test_threshold_breach_alerts(self):
        det = SynFloodDetector(window_seconds=5.0, threshold=10)
        alerts = [det.inspect(syn("10.0.0.42")) for _ in range(20)]
        fired = [a for a in alerts if a is not None]
        assert len(fired) >= 1
        assert fired[0].detector == "syn_flood"
        assert "10.0.0.42" in fired[0].message

    def test_non_syn_packets_ignored(self):
        det = SynFloodDetector(window_seconds=5.0, threshold=2)
        # ACKs and other flags should not count.
        for _ in range(20):
            p = ParsedPacket(
                ts=time.time(), proto="TCP", src="10.0.0.42", dst="10.0.0.1",
                sport=1, dport=80, length=60, tcp_flags="A",
            )
            assert det.inspect(p) is None


class TestPortScanDetector:
    def test_distinct_ports_trigger(self):
        det = PortScanDetector(window_seconds=10.0, threshold=10)
        alerts = []
        for port in range(20, 60):
            alerts.append(det.inspect(syn("10.0.0.7", dport=port)))
        fired = [a for a in alerts if a is not None]
        assert len(fired) >= 1
        assert "10.0.0.7" in fired[0].message

    def test_repeated_same_port_no_alert(self):
        det = PortScanDetector(window_seconds=10.0, threshold=5)
        for _ in range(100):
            assert det.inspect(syn("10.0.0.7", dport=80)) is None


class TestDnsAnomalyDetector:
    def test_long_query_alerts(self):
        det = DnsAnomalyDetector(max_qname=40)
        long_q = "a" * 50 + ".example.com"
        a = det.inspect(dns_query("10.0.0.5", long_q))
        assert a is not None
        assert "Long DNS query" in a.message

    def test_high_entropy_alerts(self):
        det = DnsAnomalyDetector(entropy_threshold=3.5)
        # Random-looking subdomain (high entropy).
        dga = "xq7r9p2k8m4nv6t.example.com"
        a = det.inspect(dns_query("10.0.0.5", dga))
        assert a is not None
        assert "High-entropy" in a.message

    def test_low_entropy_no_alert(self):
        det = DnsAnomalyDetector(entropy_threshold=3.5, max_qname=200)
        a = det.inspect(dns_query("10.0.0.5", "www.google.com"))
        assert a is None

    def test_nxdomain_burst(self):
        det = DnsAnomalyDetector(nx_threshold=5, window_seconds=60)
        alerts = [det.inspect(dns_response("10.0.0.9", rcode=3)) for _ in range(10)]
        fired = [a for a in alerts if a is not None]
        assert any("NXDOMAIN" in a.message for a in fired)


class TestStatsAnomalyDetector:
    def test_no_alert_during_warmup(self):
        det = StatsAnomalyDetector(history_seconds=60, z_threshold=3.0, warmup=20)
        base = int(time.time())
        for sec_offset in range(5):
            for _ in range(10):
                p = ParsedPacket(
                    ts=base + sec_offset + 0.1, proto="TCP", src="1.1.1.1",
                    dst="2.2.2.2", sport=1, dport=2, length=60, tcp_flags="A",
                )
                assert det.inspect(p) is None

    def test_spike_after_warmup_alerts(self):
        det = StatsAnomalyDetector(history_seconds=120, z_threshold=2.0, warmup=10)
        base = int(time.time())
        # 30 quiet seconds at ~5 pps.
        for sec in range(30):
            for _ in range(5):
                p = ParsedPacket(
                    ts=base + sec + 0.1, proto="TCP", src="1.1.1.1",
                    dst="2.2.2.2", sport=1, dport=2, length=60, tcp_flags="A",
                )
                det.inspect(p)
        # spike: 200 pps in next second
        spike_alert = None
        for _ in range(200):
            p = ParsedPacket(
                ts=base + 30 + 0.5, proto="TCP", src="1.1.1.1",
                dst="2.2.2.2", sport=1, dport=2, length=60, tcp_flags="A",
            )
            det.inspect(p)
        # cross to next second so the spike bucket gets sealed
        sealed = ParsedPacket(
            ts=base + 31 + 0.1, proto="TCP", src="1.1.1.1",
            dst="2.2.2.2", sport=1, dport=2, length=60, tcp_flags="A",
        )
        spike_alert = det.inspect(sealed)
        assert spike_alert is not None
        assert "spike" in spike_alert.message.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
