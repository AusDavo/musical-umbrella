"""CLI entry point for docker-netmon."""

from __future__ import annotations

import sys

import click
from rich.console import Console

from netmon import __version__
from netmon.alerts import AlertDispatcher
from netmon.conflicts import ConflictDetector
from netmon.docker_client import DockerClient
from netmon.monitor import EventMonitor
from netmon.scanner import NetworkScanner
from netmon.visualizer import NetworkVisualizer


console = Console()


def get_client() -> DockerClient:
    """Get Docker client or exit with error."""
    try:
        return DockerClient()
    except ConnectionError as e:
        console.print(f"[red]Error:[/red] {e}")
        console.print("[dim]Is Docker running? Is the socket accessible?[/dim]")
        sys.exit(1)


@click.group()
@click.version_option(version=__version__, prog_name="netmon")
def main() -> None:
    """Docker Network Monitor - detect DNS conflicts and visualize topology."""
    pass


@main.command()
@click.option(
    "--network",
    "-n",
    help="Scan specific network only",
)
@click.option(
    "--include-default",
    is_flag=True,
    help="Include default networks (bridge, host, none)",
)
@click.option(
    "--no-warnings",
    is_flag=True,
    help="Suppress warnings for generic names",
)
@click.option(
    "--quiet",
    "-q",
    is_flag=True,
    help="Only output if conflicts found",
)
def scan(
    network: str | None,
    include_default: bool,
    no_warnings: bool,
    quiet: bool,
) -> None:
    """Scan Docker networks for DNS conflicts."""
    client = get_client()

    try:
        scanner = NetworkScanner(client)
        detector = ConflictDetector(warn_generic_names=not no_warnings)
        visualizer = NetworkVisualizer(console)

        if network:
            topology = scanner.scan_network(network)
            if not topology.networks:
                console.print(f"[yellow]Network '{network}' not found or empty[/yellow]")
                sys.exit(1)
        else:
            topology = scanner.scan(include_default_networks=include_default)

        report = detector.analyze(topology)

        if quiet and not report.has_conflicts:
            sys.exit(0)

        visualizer.render_conflict_report(report)

        if report.critical_count > 0:
            sys.exit(2)
        elif report.high_count > 0:
            sys.exit(1)
        else:
            sys.exit(0)

    finally:
        client.close()


@main.command()
@click.option(
    "--include-default",
    is_flag=True,
    help="Include default networks (bridge, host, none)",
)
def map(include_default: bool) -> None:
    """Display network topology as ASCII tree."""
    client = get_client()

    try:
        scanner = NetworkScanner(client)
        detector = ConflictDetector()
        visualizer = NetworkVisualizer(console)

        topology = scanner.scan(include_default_networks=include_default)
        report = detector.analyze(topology)

        if not topology.networks:
            console.print("[yellow]No user-defined networks found[/yellow]")
            if not include_default:
                console.print("[dim]Use --include-default to see default networks[/dim]")
            sys.exit(0)

        visualizer.render_topology(topology, report)

    finally:
        client.close()


@main.command()
@click.option(
    "--no-warnings",
    is_flag=True,
    help="Suppress warnings for generic names",
)
@click.option(
    "--no-initial-scan",
    is_flag=True,
    help="Skip initial scan on startup",
)
def watch(no_warnings: bool, no_initial_scan: bool) -> None:
    """Monitor Docker events and alert on conflicts."""
    client = get_client()

    try:
        scanner = NetworkScanner(client)
        detector = ConflictDetector(warn_generic_names=not no_warnings)
        dispatcher = AlertDispatcher.from_env()

        if not dispatcher.is_configured:
            console.print(
                "[yellow]Warning:[/yellow] No alert URL configured. "
                "Set NETMON_ALERT_URL to enable alerts."
            )
            console.print()

        monitor = EventMonitor(
            client=client,
            scanner=scanner,
            detector=detector,
            dispatcher=dispatcher,
            console=console,
        )

        monitor.start(show_initial_scan=not no_initial_scan)

    finally:
        client.close()


@main.command()
def test_alert() -> None:
    """Send a test alert to verify alerting configuration."""
    dispatcher = AlertDispatcher.from_env()

    if not dispatcher.is_configured:
        console.print("[red]Error:[/red] No alert URL configured")
        console.print("[dim]Set NETMON_ALERT_URL environment variable[/dim]")
        sys.exit(1)

    console.print("Sending test alert...")

    if dispatcher.send_test_alert():
        console.print("[green]Test alert sent successfully[/green]")
    else:
        console.print("[red]Failed to send test alert[/red]")
        sys.exit(1)


@main.command()
@click.option(
    "--port",
    "-p",
    default=8080,
    help="Port to run the web server on",
)
@click.option(
    "--host",
    "-h",
    default="0.0.0.0",
    help="Host to bind the web server to",
)
def web(port: int, host: str) -> None:
    """Start the web dashboard."""
    get_client()

    console.print(f"[bold]Docker Network Monitor[/bold] - Web Dashboard")
    console.print(f"Starting server on http://{host}:{port}")
    console.print("[dim]Press Ctrl+C to stop[/dim]\n")

    from netmon.web import run_server
    run_server(host=host, port=port)


if __name__ == "__main__":
    main()
