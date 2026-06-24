"""Producer side: Scapy AsyncSniffer that pushes ParsedPackets onto a queue."""
from __future__ import annotations

import queue
import threading
from collections import deque
from pathlib import Path
from typing import Deque, Optional

from scapy.all import AsyncSniffer, get_if_list
from scapy.packet import Packet
from scapy.utils import wrpcap

from .parser import ParsedPacket, parse


def write_pcap(raw_packets, path: str | Path) -> int:
    """Write raw Scapy packets to a libpcap file readable by Wireshark/tshark.

    Returns the number of packets written. Empty input still produces a valid
    (zero-packet) pcap so downstream tooling never trips over a missing file.
    Separated from `Capture` so it can be unit-tested with synthetic packets,
    no live sniffer (and therefore no sudo) required.
    """
    packets = list(raw_packets)
    output_path = Path(path).expanduser()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output_path), packets)
    return len(packets)


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
        pcap_buffer: int = 10000,
    ) -> None:
        self.iface = iface
        self.bpf_filter = bpf_filter
        self.queue: "queue.Queue[ParsedPacket]" = queue.Queue(maxsize=max_queue)
        self._dropped = 0
        self._sniffer: Optional[AsyncSniffer] = None
        self._lock = threading.Lock()
        # Rolling buffer of the *raw* Scapy packets so we can dump a faithful
        # .pcap on demand. The parse path keeps only the flattened ParsedPacket,
        # which loses payload bytes — useless for Wireshark interop — so we keep
        # the originals here, bounded to the most recent `pcap_buffer` packets.
        self.raw_buffer: Deque[Packet] = deque(maxlen=pcap_buffer)

    @staticmethod
    def list_interfaces() -> list[str]:
        return get_if_list()

    @property
    def dropped(self) -> int:
        return self._dropped

    def _on_packet(self, pkt) -> None:
        # Retain the raw frame first — even packets we can't parse (non-IP, etc.)
        # belong in a faithful capture. deque.append is atomic under the GIL, so
        # this is safe to call from the sniffer thread without locking.
        self.raw_buffer.append(pkt)
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

    def write_pcap(self, path: str | Path) -> int:
        """Dump the buffered raw packets to a .pcap and return the count written.

        Snapshots the ring buffer first (`list(...)` is atomic under the GIL) so
        the sniffer thread can keep appending while we write.
        """
        return write_pcap(list(self.raw_buffer), path)
