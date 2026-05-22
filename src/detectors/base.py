"""Detector protocol and Alert dataclass."""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional, Protocol

from ..parser import ParsedPacket


@dataclass(frozen=True)
class Alert:
    ts: float
    severity: str          # "info" | "warn" | "high"
    detector: str
    source: str            # the offending IP or subject
    message: str

    def short(self) -> str:
        return f"[{self.severity.upper():<4}] {self.detector}: {self.message}"


class Detector(Protocol):
    name: str

    def inspect(self, pkt: ParsedPacket) -> Optional[Alert]:
        """Examine one packet. Return an Alert if something triggered."""
        ...


class CooldownMixin:
    """Mixin: suppress repeated alerts for the same source within `cooldown` seconds."""

    cooldown_seconds: float = 10.0

    def __init__(self) -> None:
        self._last_alert: dict[str, float] = {}

    def _can_alert(self, source: str, now: float | None = None) -> bool:
        current = time.time() if now is None else now
        last = self._last_alert.get(source)
        if last is None or current - last >= self.cooldown_seconds:
            self._last_alert[source] = current
            return True
        return False
