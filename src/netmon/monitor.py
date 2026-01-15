"""Docker event monitoring for real-time conflict detection."""

from __future__ import annotations

import signal
import sys
import time
from typing import TYPE_CHECKING

from rich.console import Console

from netmon.conflicts import ConflictDetector
from netmon.docker_client import DockerClient
from netmon.scanner import NetworkScanner
from netmon.visualizer import NetworkVisualizer

if TYPE_CHECKING:
    from netmon.alerts import AlertDispatcher


class EventMonitor:
    """Monitors Docker events for network changes."""

    RELEVANT_EVENTS = {
        ("container", "start"),
        ("container", "stop"),
        ("container", "die"),
        ("network", "connect"),
        ("network", "disconnect"),
    }

    DEBOUNCE_SECONDS = 2.0

    def __init__(
        self,
        client: DockerClient,
        scanner: NetworkScanner,
        detector: ConflictDetector,
        dispatcher: AlertDispatcher | None = None,
        console: Console | None = None,
    ) -> None:
        self._client = client
        self._scanner = scanner
        self._detector = detector
        self._dispatcher = dispatcher
        self._console = console or Console()
        self._visualizer = NetworkVisualizer(self._console)
        self._running = False
        self._last_scan_time = 0.0
        self._pending_scan = False

    def start(self, show_initial_scan: bool = True) -> None:
        """Start monitoring Docker events."""
        self._running = True
        self._setup_signal_handlers()

        self._console.print("[bold]Docker Network Monitor[/bold]")
        self._console.print("Watching for network changes... (Ctrl+C to stop)\n")

        if self._dispatcher and self._dispatcher.is_configured:
            self._console.print("[dim]Alerting is enabled[/dim]\n")

        if show_initial_scan:
            self._perform_scan(initial=True)

        try:
            for event in self._client.watch_events():
                if not self._running:
                    break

                event_type = event.get("Type", "")
                action = event.get("Action", "")

                if (event_type, action) in self.RELEVANT_EVENTS:
                    self._handle_event(event)

        except KeyboardInterrupt:
            pass
        finally:
            self._console.print("\n[dim]Stopped monitoring[/dim]")

    def stop(self) -> None:
        """Stop monitoring."""
        self._running = False

    def _setup_signal_handlers(self) -> None:
        """Set up signal handlers for graceful shutdown."""
        def handle_signal(signum: int, frame: object) -> None:
            self.stop()

        signal.signal(signal.SIGTERM, handle_signal)
        signal.signal(signal.SIGINT, handle_signal)

    def _handle_event(self, event: dict) -> None:
        """Handle a Docker event."""
        event_type = event.get("Type", "")
        action = event.get("Action", "")
        actor = event.get("Actor", {})
        attributes = actor.get("Attributes", {})

        name = attributes.get("name", actor.get("ID", "unknown")[:12])

        self._console.print(
            f"[dim]{time.strftime('%H:%M:%S')}[/dim] "
            f"[cyan]{event_type}[/cyan]:[yellow]{action}[/yellow] {name}"
        )

        now = time.time()
        if now - self._last_scan_time >= self.DEBOUNCE_SECONDS:
            self._perform_scan()
        else:
            self._pending_scan = True

    def _perform_scan(self, initial: bool = False) -> None:
        """Perform a network scan and check for conflicts."""
        self._last_scan_time = time.time()
        self._pending_scan = False

        try:
            topology = self._scanner.scan()
            report = self._detector.analyze(topology)

            if not initial:
                self._console.print()

            self._visualizer.render_summary(report)

            if report.has_conflicts:
                self._console.print()
                self._visualizer.render_conflict_report(report)

                if self._dispatcher and self._dispatcher.is_configured:
                    if self._dispatcher.send_conflict_alert(report):
                        self._console.print("[dim]Alert sent[/dim]")
                    else:
                        self._console.print("[red]Failed to send alert[/red]")

            if not initial:
                self._console.print()

        except Exception as e:
            self._console.print(f"[red]Scan error: {e}[/red]")
