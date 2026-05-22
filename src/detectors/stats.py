"""Statistical anomaly detection: rolling z-score on packets/sec."""
from __future__ import annotations

import math
from collections import deque
from typing import Optional

from ..parser import ParsedPacket
from .base import Alert, CooldownMixin


class StatsAnomalyDetector(CooldownMixin):
    """Bins packets into 1-second buckets and tracks per-second packet count.
    Uses a rolling z-score: spikes above `z_threshold` standard deviations
    from the recent mean fire an alert. No training data needed.
    """

    name = "stats_anomaly"
    cooldown_seconds = 10.0

    def __init__(
        self,
        history_seconds: int = 60,
        z_threshold: float = 3.0,
        warmup: int = 20,
    ) -> None:
        super().__init__()
        self.history = history_seconds
        self.z_threshold = z_threshold
        self.warmup = warmup
        self._buckets: deque[tuple[int, int]] = deque()  # (epoch_second, count)
        self._current_sec: Optional[int] = None
        self._current_count: int = 0

    def _flush_current(self, now_sec: int) -> Optional[int]:
        """Push the just-completed second's bucket and return its count."""
        if self._current_sec is None:
            self._current_sec = now_sec
            return None
        if now_sec == self._current_sec:
            return None
        # second boundary crossed; seal the previous bucket
        completed = (self._current_sec, self._current_count)
        self._buckets.append(completed)
        self._current_sec = now_sec
        self._current_count = 0

        # trim to history window
        cutoff = now_sec - self.history
        while self._buckets and self._buckets[0][0] < cutoff:
            self._buckets.popleft()
        return completed[1]

    def inspect(self, pkt: ParsedPacket) -> Optional[Alert]:
        now_sec = int(pkt.ts)
        completed_count = self._flush_current(now_sec)
        self._current_count += 1

        if completed_count is None or len(self._buckets) < self.warmup:
            return None

        # compute mean/stdev over the sealed buckets
        counts = [c for _, c in self._buckets]
        n = len(counts)
        mean = sum(counts) / n
        var = sum((c - mean) ** 2 for c in counts) / n
        stdev = math.sqrt(var)

        if stdev <= 0:
            return None

        z = (completed_count - mean) / stdev
        if z >= self.z_threshold and self._can_alert("global_pps", pkt.ts):
            return Alert(
                ts=pkt.ts,
                severity="warn",
                detector=self.name,
                source="*",
                message=(
                    f"PPS spike: {completed_count}/s vs mean {mean:.1f} "
                    f"(z={z:.1f}, threshold {self.z_threshold})"
                ),
            )
        return None
