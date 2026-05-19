# Packet Analyzer

A Wireshark-lite terminal app that captures packets, parses protocols (TCP/UDP/HTTP/DNS), and detects suspicious traffic in real time.

Built by Seif Osman.

## Features

- **Live capture** via Scapy's `AsyncSniffer` (libpcap under the hood)
- **Protocol parsing**: Ethernet → IP → TCP/UDP → HTTP/DNS
- **Filtering**: BPF filters at the kernel level (e.g. `tcp port 443`)
- **Detectors**:
  - SYN flood (half-open connections per source)
  - Port scan (unique destination ports per source)
  - DNS anomalies (long queries, high entropy, TXT volume, NXDOMAIN bursts)
  - Statistical anomaly (rolling z-score on packets/sec and bytes/sec)
- **Real-time TUI dashboard** built with Textual: live feed, rolling stats, alerts panel

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
```

Press `q` to quit, `p` to pause/resume the live feed, `c` to clear alerts.

## Project layout

```
packet-analyzer/
├── sniffer.py              # CLI entry point
├── requirements.txt
├── src/
│   ├── capture.py          # Scapy AsyncSniffer wrapper (producer)
│   ├── parser.py           # Protocol field extraction
│   ├── state.py            # Shared state + ring buffer
│   ├── dashboard.py        # Textual TUI (consumer)
│   └── detectors/
│       ├── base.py
│       ├── syn_flood.py
│       ├── port_scan.py
│       ├── dns_anomaly.py
│       └── stats.py
└── tests/
    └── test_detectors.py
```

## Safety / ethics

This tool is for **authorized** network monitoring, defensive analysis, and education. Run it only on networks you own or have permission to monitor.
