"""Shared state: rolling stats + bounded ring buffers for feed and alerts."""
from __future__ import annotations

import time
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Deque

from .detectors.base import Alert
from .parser import ParsedPacket


@dataclass
class State:
    feed: Deque[ParsedPacket] = field(default_factory=lambda: deque(maxlen=200))
    alerts: Deque[Alert] = field(default_factory=lambda: deque(maxlen=100))

    total_packets: int = 0
    total_bytes: int = 0
    started_at: float = field(default_factory=time.time)
    protocol_counts: Counter[str] = field(default_factory=Counter)
    source_counts: Counter[str] = field(default_factory=Counter)
    destination_counts: Counter[str] = field(default_factory=Counter)
    flow_counts: Counter[str] = field(default_factory=Counter)

    # Rolling window for pps/bps computation.
    _window: Deque[tuple[float, int]] = field(default_factory=lambda: deque(maxlen=600))
    paused: bool = False

    def ingest(self, pkt: ParsedPacket) -> None:
        self.total_packets += 1
        self.total_bytes += pkt.length
        self.protocol_counts[pkt.proto] += 1
        self.source_counts[pkt.src] += 1
        self.destination_counts[pkt.dst] += 1
        self.flow_counts[f"{pkt.src} -> {pkt.dst}"] += 1
        self._window.append((pkt.ts, pkt.length))
        if not self.paused:
            self.feed.append(pkt)

    def record_alert(self, alert: Alert) -> None:
        self.alerts.append(alert)

    def pps(self, window_seconds: float = 5.0) -> float:
        if not self._window:
            return 0.0
        cutoff = time.time() - window_seconds
        recent = [w for w in self._window if w[0] >= cutoff]
        return len(recent) / window_seconds if recent else 0.0

    def bps(self, window_seconds: float = 5.0) -> float:
        if not self._window:
            return 0.0
        cutoff = time.time() - window_seconds
        recent = [w for w in self._window if w[0] >= cutoff]
        return sum(w[1] for w in recent) / window_seconds if recent else 0.0

    def clear_alerts(self) -> None:
        self.alerts.clear()

    def top_sources(self, limit: int = 5) -> list[tuple[str, int]]:
        return self.source_counts.most_common(limit)

    def top_destinations(self, limit: int = 5) -> list[tuple[str, int]]:
        return self.destination_counts.most_common(limit)

    def top_flows(self, limit: int = 5) -> list[tuple[str, int]]:
        return self.flow_counts.most_common(limit)
