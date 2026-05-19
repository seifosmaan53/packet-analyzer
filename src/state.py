"""Shared state: rolling stats + bounded ring buffers for feed and alerts."""
from __future__ import annotations

import time
from collections import deque
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

    # Rolling window for pps/bps computation.
    _window: Deque[tuple[float, int]] = field(default_factory=lambda: deque(maxlen=600))
    paused: bool = False

    def ingest(self, pkt: ParsedPacket) -> None:
        self.total_packets += 1
        self.total_bytes += pkt.length
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
