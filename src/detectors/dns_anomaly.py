"""DNS anomaly detection: long queries, high-entropy labels, TXT volume, NXDOMAIN bursts."""
from __future__ import annotations

import math
from collections import Counter, defaultdict, deque
from typing import Optional

from ..parser import ParsedPacket
from .base import Alert, CooldownMixin


def _shannon_entropy(s: str) -> float:
    """Bits per character. Random DGA-like names score ~4+, real domains ~3."""
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


class DnsAnomalyDetector(CooldownMixin):
    """Heuristics:
      1. Query name longer than `max_qname` chars (potential exfil channel)
      2. Subdomain entropy above `entropy_threshold` (DGA / tunneling sign)
      3. > `txt_threshold` TXT queries from one source per window
      4. > `nx_threshold` NXDOMAIN responses to one source per window
    """

    name = "dns_anomaly"
    cooldown_seconds = 12.0

    def __init__(
        self,
        max_qname: int = 60,
        entropy_threshold: float = 4.0,
        window_seconds: float = 30.0,
        txt_threshold: int = 20,
        nx_threshold: int = 30,
    ) -> None:
        super().__init__()
        self.max_qname = max_qname
        self.entropy_threshold = entropy_threshold
        self.window = window_seconds
        self.txt_threshold = txt_threshold
        self.nx_threshold = nx_threshold
        self._txt_log: dict[str, deque[float]] = defaultdict(deque)
        self._nx_log: dict[str, deque[float]] = defaultdict(deque)

    def inspect(self, pkt: ParsedPacket) -> Optional[Alert]:
        if not pkt.dns_query and pkt.dns_response_code is None:
            return None

        # Rule 4: NXDOMAIN burst (rcode==3 in responses).
        if pkt.dns_response_code == 3:
            bucket = self._nx_log[pkt.dst]   # dst is the client receiving NXDOMAIN
            bucket.append(pkt.ts)
            cutoff = pkt.ts - self.window
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= self.nx_threshold and self._can_alert(f"nx:{pkt.dst}", pkt.ts):
                return Alert(
                    ts=pkt.ts,
                    severity="warn",
                    detector=self.name,
                    source=pkt.dst,
                    message=(
                        f"NXDOMAIN burst: {pkt.dst} received {len(bucket)} "
                        f"NXDOMAIN in {self.window:.0f}s (possible DGA)"
                    ),
                )

        if not pkt.dns_query:
            return None

        q = pkt.dns_query

        # Rule 1: very long query name.
        if len(q) >= self.max_qname and self._can_alert(f"long:{pkt.src}", pkt.ts):
            return Alert(
                ts=pkt.ts,
                severity="warn",
                detector=self.name,
                source=pkt.src,
                message=f"Long DNS query ({len(q)} chars) from {pkt.src}: {q[:80]}",
            )

        # Rule 2: high subdomain entropy.
        labels = q.split(".")
        if labels:
            longest = max(labels, key=len)
            if len(longest) >= 12:
                ent = _shannon_entropy(longest)
                if ent >= self.entropy_threshold and self._can_alert(f"ent:{pkt.src}", pkt.ts):
                    return Alert(
                        ts=pkt.ts,
                        severity="warn",
                        detector=self.name,
                        source=pkt.src,
                        message=(
                            f"High-entropy DNS label from {pkt.src} "
                            f"(entropy={ent:.2f}): {q[:80]}"
                        ),
                    )

        # Rule 3: TXT query volume (qtype 16).
        if pkt.dns_qtype == 16:
            bucket = self._txt_log[pkt.src]
            bucket.append(pkt.ts)
            cutoff = pkt.ts - self.window
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= self.txt_threshold and self._can_alert(f"txt:{pkt.src}", pkt.ts):
                return Alert(
                    ts=pkt.ts,
                    severity="warn",
                    detector=self.name,
                    source=pkt.src,
                    message=(
                        f"DNS TXT flood: {pkt.src} sent {len(bucket)} TXT queries "
                        f"in {self.window:.0f}s (possible DNS exfil)"
                    ),
                )

        return None
