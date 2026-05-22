"""Detect SYN floods: many SYN packets without ACK from one source."""
from __future__ import annotations

from collections import defaultdict, deque
from typing import Optional

from ..parser import ParsedPacket
from .base import Alert, CooldownMixin


class SynFloodDetector(CooldownMixin):
    """A SYN flood is a half-open-connection storm: SYNs that never get
    paired with the client's ACK. We count SYN-only TCP packets per source
    in a sliding window and alert when the rate crosses a threshold.
    """

    name = "syn_flood"
    cooldown_seconds = 15.0

    def __init__(self, window_seconds: float = 5.0, threshold: int = 100) -> None:
        super().__init__()
        self.window = window_seconds
        self.threshold = threshold
        self._syns: dict[str, deque[float]] = defaultdict(deque)

    def inspect(self, pkt: ParsedPacket) -> Optional[Alert]:
        if pkt.proto != "TCP" or pkt.tcp_flags != "S":
            return None

        bucket = self._syns[pkt.src]
        bucket.append(pkt.ts)

        cutoff = pkt.ts - self.window
        while bucket and bucket[0] < cutoff:
            bucket.popleft()

        if len(bucket) >= self.threshold and self._can_alert(pkt.src, pkt.ts):
            return Alert(
                ts=pkt.ts,
                severity="high",
                detector=self.name,
                source=pkt.src,
                message=(
                    f"SYN flood: {len(bucket)} SYNs from {pkt.src} "
                    f"in {self.window:.0f}s (threshold {self.threshold})"
                ),
            )
        return None
