#!/usr/bin/env python3
"""Packet Analyzer — CLI entry point.

Usage:
    sudo python sniffer.py                 # default interface
    sudo python sniffer.py --list          # list interfaces
    sudo python sniffer.py -i en0          # capture on en0
    sudo python sniffer.py -f "udp port 53"  # BPF filter
"""
from __future__ import annotations

import argparse
import sys

from src.capture import Capture
from src.dashboard import PacketAnalyzerApp


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
    args = parser.parse_args()

    if args.list:
        for name in Capture.list_interfaces():
            print(name)
        return 0

    app = PacketAnalyzerApp(iface=args.iface, bpf=args.bpf)
    app.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
