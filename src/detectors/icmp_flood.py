"""ICMP flood detection for ping/echo storms."""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque

from .base import Alert, CooldownMixin
from ..parser import ParsedPacket


@dataclass
class IcmpFloodDetector(CooldownMixin):
    """Detect many ICMP packets from one source in a short window."""

    threshold: int = 40
    window_seconds: float = 5.0
    cooldown_seconds: float = 10.0
    name: str = "icmp_flood"
    _hits: dict[str, Deque[float]] = field(default_factory=lambda: defaultdict(deque))

    def __post_init__(self) -> None:
        CooldownMixin.__init__(self)

    def inspect(self, pkt: ParsedPacket) -> Alert | None:
        if pkt.proto not in ("ICMP", "ICMPv6"):
            return None

        hits = self._hits[pkt.src]
        hits.append(pkt.ts)
        cutoff = pkt.ts - self.window_seconds
        while hits and hits[0] < cutoff:
            hits.popleft()

        if len(hits) >= self.threshold and self._can_alert(pkt.src, pkt.ts):
            return Alert(
                ts=pkt.ts,
                severity="high",
                detector=self.name,
                source=pkt.src,
                message=(
                    f"{len(hits)} ICMP packets from {pkt.src} "
                    f"in {self.window_seconds:.0f}s — possible ping flood"
                ),
            )
        return None
