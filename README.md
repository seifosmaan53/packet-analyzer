# Packet Analyzer

A Wireshark-lite terminal app that captures packets, parses protocols (TCP/UDP/ICMP/HTTP/DNS), detects suspicious traffic in real time, and can analyze PCAP files offline with clean JSON/CSV exports.

Built by Seif Osman.

## Features

- **Live capture** via Scapy's `AsyncSniffer` (libpcap under the hood)
- **Offline PCAP analysis** with `--pcap` for demos, labs, and investigations without sudo
- **Protocol parsing**: Ethernet → IP/IPv6 → TCP/UDP/ICMP → HTTP/DNS
- **Filtering**: BPF filters at the kernel level (e.g. `tcp port 443`)
- **Exports**: JSON reports plus packet-level JSON/CSV output for sharing or notebooks
- **Detectors**:
  - SYN flood (half-open connections per source)
  - ICMP flood / ping storm detection
  - Port scan (unique destination ports per source)
  - DNS anomalies (long queries, high entropy, TXT volume, NXDOMAIN bursts)
  - Statistical anomaly (rolling z-score on packets/sec and bytes/sec)
- **Real-time TUI dashboard** built with Textual: live feed, rolling stats, top talker, protocol mix, and alerts panel
- **Simple CLI**: one command for live capture, one command for PCAP reports

## Requirements

- Python 3.10+
- macOS / Linux (Windows works but needs Npcap)
- `sudo`/root privileges for raw packet capture

## Install

```bash
cd ~/projects/packet-analyzer
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run

```bash
# List available interfaces
sudo python sniffer.py --list

# Capture on the default interface
sudo python sniffer.py

# Capture on a specific interface with a BPF filter
sudo python sniffer.py -i en0 -f "tcp or udp port 53"

# Analyze a PCAP offline and print a clean terminal report
python sniffer.py --pcap sample.pcap

# Save a report and packet table for sharing/analysis
python sniffer.py --pcap sample.pcap \
  --json reports/summary.json \
  --packets-json reports/packets.json \
  --packets-csv reports/packets.csv
```

Press `q` to quit, `p` to pause/resume the live feed, `c` to clear alerts.

## What the dashboard shows

- Live packet feed with source, destination, protocol, and useful info
- Rolling packet rate and bandwidth
- Top talker and protocol mix in the stats bar
- Alert stream with severity colors

## Offline report output

`--pcap` prints a concise summary:

```text
Packet Analyzer Report
Source: sample.pcap
Packets: 120
Bytes: 98420
Duration: 14.20s
Protocols: TCP=80, UDP=35, ICMP=5
Top sources: 10.0.0.5=42, 10.0.0.9=21
Alerts: icmp_flood=1
```

## Project layout

```
packet-analyzer/
├── sniffer.py              # CLI entry point
├── requirements.txt
├── src/
│   ├── capture.py          # Scapy AsyncSniffer wrapper (producer)
│   ├── parser.py           # Protocol field extraction
│   ├── state.py            # Shared state + ring buffer + top talkers
│   ├── exporters.py        # JSON/CSV export helpers
│   ├── reporting.py        # Offline PCAP analysis summaries
│   ├── dashboard.py        # Textual TUI (consumer)
│   └── detectors/
│       ├── base.py
│       ├── syn_flood.py
│       ├── icmp_flood.py
│       ├── port_scan.py
│       ├── dns_anomaly.py
│       └── stats.py
└── tests/
    ├── test_detectors.py
    ├── test_parser.py
    └── test_upgrade_features.py
```

## Safety / ethics

This tool is for **authorized** network monitoring, defensive analysis, and education. Run it only on networks you own or have permission to monitor.
