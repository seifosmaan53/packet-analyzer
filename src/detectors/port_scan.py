"""Detect port scans: one source touching many distinct dest ports."""
from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Optional

from ..parser import ParsedPacket
from .base import Alert, CooldownMixin


class PortScanDetector(CooldownMixin):
    """Horizontal scan: same destination, many ports. We track the set of
    (dst, dport) tuples seen per source within a sliding window. A high
    unique-port count from a single source is the canonical scan signature.
    """

    name = "port_scan"
    cooldown_seconds = 20.0

    def __init__(self, window_seconds: float = 10.0, threshold: int = 30) -> None:
        super().__init__()
        self.window = window_seconds
        self.threshold = threshold
        # per-source: deque of (ts, dst, dport)
        self._touches: dict[str, deque[tuple[float, str, int]]] = defaultdict(deque)

    def inspect(self, pkt: ParsedPacket) -> Optional[Alert]:
        if pkt.proto not in ("TCP", "UDP") or pkt.dport is None:
            return None

        # Only count "probe-like" packets: TCP SYN or UDP. Established TCP
        # would create noise from normal multi-port apps.
        if pkt.proto == "TCP" and pkt.tcp_flags != "S":
            return None

        bucket = self._touches[pkt.src]
        bucket.append((pkt.ts, pkt.dst, pkt.dport))

        cutoff = pkt.ts - self.window
        while bucket and bucket[0][0] < cutoff:
            bucket.popleft()

        unique_ports = {(dst, port) for _, dst, port in bucket}
        if len(unique_ports) >= self.threshold and self._can_alert(pkt.src):
            distinct_dests = len({d for d, _ in unique_ports})
            return Alert(
                ts=time.time(),
                severity="high",
                detector=self.name,
                source=pkt.src,
                message=(
                    f"Port scan: {pkt.src} touched {len(unique_ports)} unique ports "
                    f"across {distinct_dests} host(s) in {self.window:.0f}s"
                ),
            )
        return None
