#!/usr/bin/env python3
"""Packet Analyzer — CLI entry point.

Usage:
    sudo python sniffer.py                     # default live interface
    sudo python sniffer.py --list              # list interfaces
    sudo python sniffer.py -i en0              # capture on en0
    sudo python sniffer.py -f "udp port 53"    # BPF filter
    python sniffer.py --pcap sample.pcap       # offline PCAP report
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from src.capture import Capture
from src.dashboard import PacketAnalyzerApp
from src.exporters import packets_to_csv, packets_to_json
from src.reporting import analyze_pcap, render_report


def main() -> int:
    parser = argparse.ArgumentParser(description="Wireshark-lite TUI sniffer.")
    parser.add_argument("-i", "--iface", help="Interface to capture on", default=None)
    parser.add_argument(
        "-f",
        "--filter",
        dest="bpf",
        help='BPF filter, e.g. "tcp or udp port 53"',
        default=None,
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available interfaces and exit",
    )
    parser.add_argument(
        "--pcap",
        help="Analyze a PCAP file offline instead of starting live capture",
    )
    parser.add_argument(
        "--json",
        dest="json_path",
        help="Write an offline analysis report to this JSON file",
    )
    parser.add_argument(
        "--packets-json",
        help="Write parsed packet rows from an offline analysis to this JSON file",
    )
    parser.add_argument(
        "--packets-csv",
        help="Write parsed packet rows from an offline analysis to this CSV file",
    )
    args = parser.parse_args()

    if args.list:
        for name in Capture.list_interfaces():
            print(name)
        return 0

    export_flags = [args.json_path, args.packets_json, args.packets_csv]
    if any(export_flags) and not args.pcap:
        parser.error("--json/--packets-json/--packets-csv require --pcap")

    if args.pcap:
        report = analyze_pcap(args.pcap)
        print(render_report(report))
        if args.json_path:
            _write_text(args.json_path, json.dumps(report.to_dict(), indent=2, sort_keys=True))
        if args.packets_json:
            _write_text(args.packets_json, packets_to_json(report.packets))
        if args.packets_csv:
            _write_text(args.packets_csv, packets_to_csv(report.packets))
        return 0

    app = PacketAnalyzerApp(iface=args.iface, bpf=args.bpf)
    app.run()
    return 0


def _write_text(path: str, content: str) -> None:
    output_path = Path(path).expanduser()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
