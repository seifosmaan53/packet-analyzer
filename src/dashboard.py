"""Consumer side: Textual TUI that drives the capture and detectors."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import DataTable, Footer, Header, Static

from .capture import Capture
from .detectors import (
    Detector,
    DnsAnomalyDetector,
    PortScanDetector,
    StatsAnomalyDetector,
    SynFloodDetector,
)
from .state import State


SEVERITY_COLOR = {
    "info": "cyan",
    "warn": "yellow",
    "high": "red",
}


class StatsBar(Static):
    """Top status bar with live counters."""

    pps: reactive[float] = reactive(0.0)
    bps: reactive[float] = reactive(0.0)
    total: reactive[int] = reactive(0)
    dropped: reactive[int] = reactive(0)
    alerts: reactive[int] = reactive(0)
    paused: reactive[bool] = reactive(False)

    def render(self) -> str:
        kbps = self.bps * 8 / 1000.0
        pause_tag = "  [yellow]PAUSED[/yellow]" if self.paused else ""
        return (
            f" [b]Packets[/b] {self.total:>7}   "
            f"[b]PPS[/b] {self.pps:>6.1f}   "
            f"[b]Kbps[/b] {kbps:>7.1f}   "
            f"[b]Dropped[/b] {self.dropped}   "
            f"[b]Alerts[/b] {self.alerts}{pause_tag}"
        )


class PacketAnalyzerApp(App):
    """Main Textual app. Drives the sniffer, detectors, and live UI."""

    CSS = """
    Screen { layout: vertical; }
    StatsBar { dock: top; height: 1; background: $accent; color: $text; }
    #body { height: 1fr; }
    #feed { width: 2fr; border: solid $accent; }
    #alerts { width: 1fr; border: solid $warning; }
    DataTable { height: 1fr; }
    #feed > .title, #alerts > .title { background: $accent 20%; padding: 0 1; }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("p", "toggle_pause", "Pause/Resume"),
        Binding("c", "clear_alerts", "Clear alerts"),
    ]

    def __init__(self, iface: Optional[str] = None, bpf: Optional[str] = None) -> None:
        super().__init__()
        self.capture = Capture(iface=iface, bpf_filter=bpf)
        self.state = State()
        self.detectors: list[Detector] = [
            SynFloodDetector(),
            PortScanDetector(),
            DnsAnomalyDetector(),
            StatsAnomalyDetector(),
        ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield StatsBar(id="stats")
        with Horizontal(id="body"):
            with Vertical(id="feed"):
                yield Static("[b]Live Feed[/b]", classes="title")
                feed = DataTable(id="feed_table", zebra_stripes=True, cursor_type="row")
                feed.add_columns("Time", "Src", "Dst", "Proto", "Info")
                yield feed
            with Vertical(id="alerts"):
                yield Static("[b]Alerts[/b]", classes="title")
                alerts = DataTable(id="alerts_table", zebra_stripes=True)
                alerts.add_columns("Time", "Sev", "Detector", "Message")
                yield alerts
        yield Footer()

    def on_mount(self) -> None:
        self.capture.start()
        # Drain & redraw at 5 Hz.
        self.set_interval(0.2, self._tick)

    async def on_unmount(self) -> None:
        self.capture.stop()

    def _tick(self) -> None:
        batch = self.capture.drain(max_items=500)
        feed_table = self.query_one("#feed_table", DataTable)
        alerts_table = self.query_one("#alerts_table", DataTable)

        for pkt in batch:
            self.state.ingest(pkt)
            for det in self.detectors:
                alert = det.inspect(pkt)
                if alert is not None:
                    self.state.record_alert(alert)
                    color = SEVERITY_COLOR.get(alert.severity, "white")
                    alerts_table.add_row(
                        datetime.fromtimestamp(alert.ts).strftime("%H:%M:%S"),
                        f"[{color}]{alert.severity.upper()}[/{color}]",
                        alert.detector,
                        alert.message,
                    )

            if not self.state.paused:
                info = ""
                if pkt.tcp_flags:
                    info = f"[{pkt.tcp_flags}] {pkt.sport}->{pkt.dport}"
                elif pkt.dns_query:
                    info = f"DNS? {pkt.dns_query}"
                elif pkt.http_method:
                    info = f"HTTP {pkt.http_method} {pkt.http_host or ''}{pkt.http_path or ''}"
                elif pkt.sport is not None:
                    info = f"{pkt.sport}->{pkt.dport}"

                feed_table.add_row(
                    datetime.fromtimestamp(pkt.ts).strftime("%H:%M:%S"),
                    pkt.src,
                    pkt.dst,
                    pkt.proto,
                    info,
                )

        # Trim DataTable to match the ring-buffer bounds (avoid unbounded growth).
        while feed_table.row_count > (self.state.feed.maxlen or 0):
            feed_table.remove_row(next(iter(feed_table.rows)))
        while alerts_table.row_count > (self.state.alerts.maxlen or 0):
            alerts_table.remove_row(next(iter(alerts_table.rows)))

        stats = self.query_one(StatsBar)
        stats.pps = self.state.pps()
        stats.bps = self.state.bps()
        stats.total = self.state.total_packets
        stats.dropped = self.capture.dropped
        stats.alerts = len(self.state.alerts)
        stats.paused = self.state.paused

    def action_toggle_pause(self) -> None:
        self.state.paused = not self.state.paused

    def action_clear_alerts(self) -> None:
        self.state.clear_alerts()
        self.query_one("#alerts_table", DataTable).clear()
