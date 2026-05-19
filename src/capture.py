"""Producer side: Scapy AsyncSniffer that pushes ParsedPackets onto a queue."""
from __future__ import annotations

import queue
import threading
from typing import Optional

from scapy.all import AsyncSniffer, conf, get_if_list

from .parser import ParsedPacket, parse


class Capture:
    """Wraps Scapy's AsyncSniffer with backpressure and a parsed-packet queue.

    The sniffer runs in its own OS thread (Scapy spawns it). We push parsed
    packets onto a bounded queue; if the consumer falls behind, we drop the
    oldest entries to keep the sniffer thread non-blocking.
    """

    def __init__(
        self,
        iface: Optional[str] = None,
        bpf_filter: Optional[str] = None,
        max_queue: int = 5000,
    ) -> None:
        self.iface = iface
        self.bpf_filter = bpf_filter
        self.queue: "queue.Queue[ParsedPacket]" = queue.Queue(maxsize=max_queue)
        self._dropped = 0
        self._sniffer: Optional[AsyncSniffer] = None
        self._lock = threading.Lock()

    @staticmethod
    def list_interfaces() -> list[str]:
        return get_if_list()

    @property
    def dropped(self) -> int:
        return self._dropped

    def _on_packet(self, pkt) -> None:
        parsed = parse(pkt)
        if parsed is None:
            return
        try:
            self.queue.put_nowait(parsed)
        except queue.Full:
            # Drop oldest, push newest. Better to lose a stale packet than
            # block the sniffer thread (which would cause kernel drops).
            with self._lock:
                try:
                    self.queue.get_nowait()
                    self._dropped += 1
                except queue.Empty:
                    pass
                try:
                    self.queue.put_nowait(parsed)
                except queue.Full:
                    self._dropped += 1

    def start(self) -> None:
        kwargs = {"prn": self._on_packet, "store": False}
        if self.iface:
            kwargs["iface"] = self.iface
        if self.bpf_filter:
            kwargs["filter"] = self.bpf_filter
        self._sniffer = AsyncSniffer(**kwargs)
        self._sniffer.start()

    def stop(self) -> None:
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                # Scapy raises if sniffer never received a packet; harmless.
                pass
            self._sniffer = None

    def drain(self, max_items: int = 500) -> list[ParsedPacket]:
        """Pull up to max_items off the queue without blocking."""
        items: list[ParsedPacket] = []
        for _ in range(max_items):
            try:
                items.append(self.queue.get_nowait())
            except queue.Empty:
                break
        return items
