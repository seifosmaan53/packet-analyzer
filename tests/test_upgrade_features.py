from __future__ import annotations

import json

from src.detectors.base import Alert
from src.detectors.icmp_flood import IcmpFloodDetector
from src.detectors.syn_flood import SynFloodDetector
from src.exporters import alerts_to_json, packets_to_csv, packets_to_json
from src.parser import ParsedPacket
from src.reporting import AnalysisReport, build_report
from src.state import State


def pkt(
    *,
    ts: float = 1.0,
    proto: str = "TCP",
    src: str = "10.0.0.1",
    dst: str = "10.0.0.2",
    length: int = 100,
    sport: int | None = 12345,
    dport: int | None = 80,
    tcp_flags: str | None = "S",
) -> ParsedPacket:
    return ParsedPacket(
        ts=ts,
        proto=proto,
        src=src,
        dst=dst,
        sport=sport,
        dport=dport,
        length=length,
        tcp_flags=tcp_flags,
        summary=f"{proto} {src}->{dst}",
    )


def test_state_tracks_protocol_counts_and_top_talkers() -> None:
    state = State()
    state.ingest(pkt(proto="TCP", src="10.0.0.1", dst="10.0.0.2", length=150))
    state.ingest(pkt(proto="UDP", src="10.0.0.1", dst="10.0.0.3", length=50))
    state.ingest(pkt(proto="TCP", src="10.0.0.4", dst="10.0.0.2", length=200))

    assert state.protocol_counts == {"TCP": 2, "UDP": 1}
    assert state.top_sources(limit=2) == [("10.0.0.1", 2), ("10.0.0.4", 1)]
    assert state.top_destinations(limit=1) == [("10.0.0.2", 2)]
    assert state.top_flows(limit=1) == [("10.0.0.1 -> 10.0.0.2", 1)]


def test_icmp_flood_detector_alerts_on_repeated_icmp_from_one_source() -> None:
    detector = IcmpFloodDetector(threshold=3, window_seconds=10, cooldown_seconds=0)

    alerts = [
        detector.inspect(pkt(ts=float(i), proto="ICMP", src="10.0.0.9", dst="10.0.0.1"))
        for i in range(3)
    ]

    assert alerts[-1] is not None
    assert alerts[-1].severity == "high"
    assert alerts[-1].detector == "icmp_flood"
    assert "3 ICMP packets" in alerts[-1].message


def test_exporters_emit_machine_readable_json_and_csv() -> None:
    packets = [
        pkt(ts=1.25, proto="TCP", src="10.0.0.1", dst="10.0.0.2", sport=1111, dport=443),
        pkt(ts=2.5, proto="DNS", src="10.0.0.2", dst="10.0.0.53", sport=5353, dport=53),
    ]
    alert = Alert(ts=3.0, severity="warn", detector="demo", source="10.0.0.1", message="check this")

    packets_json = json.loads(packets_to_json(packets))
    alerts_json = json.loads(alerts_to_json([alert]))
    csv_text = packets_to_csv(packets)

    assert packets_json[0]["proto"] == "TCP"
    assert alerts_json[0]["detector"] == "demo"
    assert "ts,proto,src,dst,sport,dport,length,flags,dns_query,http" in csv_text
    assert "10.0.0.1,10.0.0.2,1111,443" in csv_text


def test_csv_export_escapes_spreadsheet_formula_cells() -> None:
    csv_text = packets_to_csv([
        pkt(proto="UDP", src="10.0.0.1", dst="10.0.0.53", dport=53),
        ParsedPacket(
            ts=1.0,
            proto="UDP",
            src="10.0.0.1",
            dst="10.0.0.53",
            dport=53,
            length=80,
            dns_query="=cmd|' /C calc'!A0",
            summary="dangerous dns",
        ),
    ])

    assert "'=cmd|' /C calc'!A0" in csv_text


def test_detector_cooldown_uses_packet_time_for_offline_bursts() -> None:
    detector = SynFloodDetector(window_seconds=5, threshold=2)
    first_burst = [
        pkt(ts=1.0, proto="TCP", src="10.0.0.8", dst="10.0.0.1", dport=80),
        pkt(ts=2.0, proto="TCP", src="10.0.0.8", dst="10.0.0.1", dport=81),
    ]
    second_burst = [
        pkt(ts=30.0, proto="TCP", src="10.0.0.8", dst="10.0.0.1", dport=82),
        pkt(ts=31.0, proto="TCP", src="10.0.0.8", dst="10.0.0.1", dport=83),
    ]

    alerts = [detector.inspect(packet) for packet in [*first_burst, *second_burst]]

    assert alerts[1] is not None
    assert alerts[1].ts == 2.0
    assert alerts[3] is not None
    assert alerts[3].ts == 31.0


def test_build_report_summarizes_packets_alerts_and_talkers() -> None:
    packets = [
        pkt(ts=1.0, proto="TCP", src="10.0.0.1", dst="10.0.0.2", length=100),
        pkt(ts=2.0, proto="TCP", src="10.0.0.1", dst="10.0.0.3", length=200),
        pkt(ts=3.0, proto="UDP", src="10.0.0.4", dst="10.0.0.2", length=50),
    ]
    alert = Alert(ts=3.0, severity="high", detector="port_scan", source="10.0.0.1", message="scan")

    report = build_report(packets, [alert], source="sample.pcap")

    assert isinstance(report, AnalysisReport)
    assert report.source == "sample.pcap"
    assert report.total_packets == 3
    assert report.total_bytes == 350
    assert report.protocol_counts == {"TCP": 2, "UDP": 1}
    assert report.top_sources[0] == ("10.0.0.1", 2)
    assert report.alert_counts == {"port_scan": 1}
    assert report.duration_seconds == 2.0
