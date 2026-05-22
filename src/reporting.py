"""Offline packet analysis reports."""
from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

from scapy.utils import PcapReader

from .detectors import (
    Detector,
    DnsAnomalyDetector,
    IcmpFloodDetector,
    PortScanDetector,
    StatsAnomalyDetector,
    SynFloodDetector,
)
from .detectors.base import Alert
from .exporters import alert_to_dict, packet_to_dict
from .parser import ParsedPacket, parse
from .state import State


@dataclass(frozen=True)
class AnalysisReport:
    source: str
    total_packets: int
    total_bytes: int
    duration_seconds: float
    protocol_counts: dict[str, int]
    top_sources: list[tuple[str, int]]
    top_destinations: list[tuple[str, int]]
    top_flows: list[tuple[str, int]]
    alert_counts: dict[str, int]
    packets: list[ParsedPacket] = field(default_factory=list, repr=False)
    alerts: list[Alert] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["packets"] = [packet_to_dict(pkt) for pkt in self.packets]
        data["alerts"] = [alert_to_dict(alert) for alert in self.alerts]
        return data


def default_detectors() -> list[Detector]:
    """Return the standard detector stack used by live and offline modes."""
    return [
        SynFloodDetector(),
        PortScanDetector(),
        DnsAnomalyDetector(),
        IcmpFloodDetector(),
        StatsAnomalyDetector(),
    ]


def build_report(
    packets: Sequence[ParsedPacket],
    alerts: Sequence[Alert],
    *,
    source: str,
    top_limit: int = 5,
) -> AnalysisReport:
    """Summarize parsed packets and alerts for humans and exports."""
    state = State()
    for pkt in packets:
        state.ingest(pkt)

    if packets:
        duration = max(pkt.ts for pkt in packets) - min(pkt.ts for pkt in packets)
    else:
        duration = 0.0

    alert_counts = Counter(alert.detector for alert in alerts)
    return AnalysisReport(
        source=source,
        total_packets=state.total_packets,
        total_bytes=state.total_bytes,
        duration_seconds=duration,
        protocol_counts=dict(state.protocol_counts),
        top_sources=state.top_sources(top_limit),
        top_destinations=state.top_destinations(top_limit),
        top_flows=state.top_flows(top_limit),
        alert_counts=dict(alert_counts),
        packets=list(packets),
        alerts=list(alerts),
    )


def analyze_packets(
    packets: Iterable[ParsedPacket],
    *,
    source: str = "packets",
    detectors: Sequence[Detector] | None = None,
) -> AnalysisReport:
    """Run parsed packets through detectors and return a report."""
    detector_stack = list(detectors) if detectors is not None else default_detectors()
    parsed_packets: list[ParsedPacket] = []
    alerts: list[Alert] = []

    for pkt in packets:
        parsed_packets.append(pkt)
        for detector in detector_stack:
            alert = detector.inspect(pkt)
            if alert is not None:
                alerts.append(alert)

    return build_report(parsed_packets, alerts, source=source)


def analyze_pcap(path: str | Path, detectors: Sequence[Detector] | None = None) -> AnalysisReport:
    """Parse a PCAP file with Scapy and analyze it without requiring sudo/live capture."""
    pcap_path = Path(path).expanduser()
    parsed_packets: list[ParsedPacket] = []
    with PcapReader(str(pcap_path)) as reader:
        for raw_packet in reader:
            parsed = parse(raw_packet)
            if parsed is not None:
                parsed_packets.append(parsed)
    return analyze_packets(parsed_packets, source=str(pcap_path), detectors=detectors)


def render_report(report: AnalysisReport) -> str:
    """Render a concise terminal-friendly report."""
    lines = [
        "Packet Analyzer Report",
        f"Source: {report.source}",
        f"Packets: {report.total_packets}",
        f"Bytes: {report.total_bytes}",
        f"Duration: {report.duration_seconds:.2f}s",
        f"Protocols: {_format_counts(report.protocol_counts)}",
        f"Top sources: {_format_pairs(report.top_sources)}",
        f"Top destinations: {_format_pairs(report.top_destinations)}",
        f"Top flows: {_format_pairs(report.top_flows)}",
        f"Alerts: {_format_counts(report.alert_counts)}",
    ]
    if report.alerts:
        lines.append("Recent alerts:")
        lines.extend(f"- {alert.short()}" for alert in report.alerts[-10:])
    return "\n".join(lines)


def _format_counts(counts: dict[str, int]) -> str:
    return ", ".join(f"{key}={value}" for key, value in sorted(counts.items())) or "none"


def _format_pairs(pairs: Sequence[tuple[str, int]]) -> str:
    return ", ".join(f"{key}={value}" for key, value in pairs) or "none"
