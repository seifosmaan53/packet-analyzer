"""Export parsed packets and alerts to portable formats."""
from __future__ import annotations

import csv
import io
import json
from dataclasses import asdict
from typing import Iterable

from .detectors.base import Alert
from .parser import ParsedPacket


PACKET_COLUMNS = [
    "ts",
    "proto",
    "src",
    "dst",
    "sport",
    "dport",
    "length",
    "flags",
    "dns_query",
    "http",
]


def packet_to_dict(pkt: ParsedPacket) -> dict[str, object]:
    """Return a stable JSON/CSV-friendly representation of a packet."""
    return {
        "ts": pkt.ts,
        "proto": pkt.proto,
        "src": pkt.src,
        "dst": pkt.dst,
        "sport": pkt.sport,
        "dport": pkt.dport,
        "length": pkt.length,
        "flags": pkt.tcp_flags,
        "dns_query": pkt.dns_query,
        "dns_qtype": pkt.dns_qtype,
        "dns_response_code": pkt.dns_response_code,
        "http_host": pkt.http_host,
        "http_path": pkt.http_path,
        "http_method": pkt.http_method,
        "summary": pkt.summary,
    }


def alert_to_dict(alert: Alert) -> dict[str, object]:
    return asdict(alert)


def packets_to_json(packets: Iterable[ParsedPacket]) -> str:
    return json.dumps([packet_to_dict(pkt) for pkt in packets], indent=2, sort_keys=True)


def alerts_to_json(alerts: Iterable[Alert]) -> str:
    return json.dumps([alert_to_dict(alert) for alert in alerts], indent=2, sort_keys=True)


def packets_to_csv(packets: Iterable[ParsedPacket]) -> str:
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=PACKET_COLUMNS)
    writer.writeheader()
    for pkt in packets:
        writer.writerow(
            {
                "ts": _csv_safe(pkt.ts),
                "proto": _csv_safe(pkt.proto),
                "src": _csv_safe(pkt.src),
                "dst": _csv_safe(pkt.dst),
                "sport": _csv_safe(pkt.sport),
                "dport": _csv_safe(pkt.dport),
                "length": _csv_safe(pkt.length),
                "flags": _csv_safe(pkt.tcp_flags),
                "dns_query": _csv_safe(pkt.dns_query),
                "http": _csv_safe(_http_label(pkt)),
            }
        )
    return output.getvalue()


def _http_label(pkt: ParsedPacket) -> str:
    if not pkt.http_method:
        return ""
    target = f"{pkt.http_host or ''}{pkt.http_path or ''}"
    return f"{pkt.http_method} {target}".strip()


def _csv_safe(value: object) -> object:
    """Prevent spreadsheet formula injection in exported CSV cells."""
    if not isinstance(value, str):
        return value
    if value.startswith(("=", "+", "-", "@")):
        return f"'{value}"
    return value
