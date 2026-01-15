"""ASCII visualization of Docker network topology."""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from netmon.conflicts import Severity
from netmon.scanner import get_all_dns_names

if TYPE_CHECKING:
    from netmon.conflicts import Conflict, ConflictReport
    from netmon.scanner import NetworkNode, NetworkTopology


class NetworkVisualizer:
    """Renders network topology and conflicts to terminal."""

    def __init__(self, console: Console | None = None) -> None:
        self._console = console or Console()

    def render_topology(
        self,
        topology: NetworkTopology,
        conflicts: ConflictReport | None = None,
    ) -> None:
        """Render the network topology as an ASCII tree."""
        conflict_lookup = self._build_conflict_lookup(conflicts) if conflicts else {}

        tree = Tree("[bold]Docker Networks[/bold]")

        for network_name in sorted(topology.networks.keys()):
            nodes = topology.networks[network_name]
            network_branch = tree.add(f"[cyan]{network_name}[/cyan]")

            for node in sorted(nodes, key=lambda n: n.container_name):
                self._add_container_node(network_branch, node, network_name, conflict_lookup)

        self._console.print(tree)

    def _add_container_node(
        self,
        branch: Tree,
        node: NetworkNode,
        network_name: str,
        conflict_lookup: dict[tuple[str, str], Conflict],
    ) -> None:
        """Add a container node to the tree."""
        dns_names = get_all_dns_names(node)

        label_parts = [f"[green]{node.container_name}[/green]"]

        if node.ip_address:
            label_parts.append(f"[dim]({node.ip_address})[/dim]")

        conflict_markers = []
        for dns_name in dns_names:
            key = (network_name, dns_name)
            if key in conflict_lookup:
                conflict = conflict_lookup[key]
                marker = self._get_conflict_marker(conflict)
                if marker not in conflict_markers:
                    conflict_markers.append(marker)

        if conflict_markers:
            label_parts.extend(conflict_markers)

        label = " ".join(label_parts)
        container_branch = branch.add(label)

        if node.service_name and node.service_name != node.container_name:
            container_branch.add(f"[dim]service: {node.service_name}[/dim]")

        if node.aliases:
            aliases_str = ", ".join(node.aliases)
            container_branch.add(f"[dim]aliases: {aliases_str}[/dim]")

    def _get_conflict_marker(self, conflict: Conflict) -> str:
        """Get the visual marker for a conflict."""
        if conflict.severity == Severity.CRITICAL:
            return "[bold red]CRITICAL[/bold red]"
        elif conflict.severity == Severity.HIGH:
            return "[bold yellow]CONFLICT[/bold yellow]"
        else:
            return "[yellow]warning[/yellow]"

    def _build_conflict_lookup(
        self, report: ConflictReport
    ) -> dict[tuple[str, str], Conflict]:
        """Build a lookup table for conflicts by (network, dns_name)."""
        lookup = {}
        for conflict in report.conflicts:
            key = (conflict.network, conflict.dns_name)
            existing = lookup.get(key)
            if existing is None or conflict.severity.value < existing.severity.value:
                lookup[key] = conflict
        return lookup

    def render_conflict_report(self, report: ConflictReport) -> None:
        """Render a detailed conflict report."""
        if not report.has_conflicts:
            self._console.print(
                Panel(
                    "[green]No conflicts detected[/green]",
                    title="Conflict Report",
                    border_style="green",
                )
            )
            return

        summary = Text()
        summary.append(f"Networks scanned: {report.total_networks}\n")
        summary.append(f"Containers found: {report.total_containers}\n")
        summary.append(f"Total conflicts: {len(report.conflicts)}\n")

        if report.critical_count > 0:
            summary.append(f"  Critical: {report.critical_count}\n", style="bold red")
        if report.high_count > 0:
            summary.append(f"  High: {report.high_count}\n", style="bold yellow")
        if report.warning_count > 0:
            summary.append(f"  Warning: {report.warning_count}\n", style="yellow")

        self._console.print(Panel(summary, title="Summary", border_style="blue"))

        table = Table(title="Detected Conflicts")
        table.add_column("Severity", style="bold")
        table.add_column("Network")
        table.add_column("DNS Name")
        table.add_column("Containers")
        table.add_column("Description", max_width=50)

        sorted_conflicts = sorted(
            report.conflicts,
            key=lambda c: (
                0 if c.severity == Severity.CRITICAL else 1 if c.severity == Severity.HIGH else 2
            ),
        )

        for conflict in sorted_conflicts:
            severity_style = {
                Severity.CRITICAL: "bold red",
                Severity.HIGH: "bold yellow",
                Severity.WARNING: "yellow",
            }[conflict.severity]

            table.add_row(
                Text(conflict.severity.value.upper(), style=severity_style),
                conflict.network,
                conflict.dns_name,
                ", ".join(conflict.container_names),
                conflict.description,
            )

        self._console.print(table)

        self._render_remediation_section(sorted_conflicts)

    def _render_remediation_section(self, conflicts: list[Conflict]) -> None:
        """Render remediation recommendations for conflicts."""
        critical_and_high = [
            c for c in conflicts if c.severity in (Severity.CRITICAL, Severity.HIGH)
        ]

        if not critical_and_high:
            return

        self._console.print()
        self._console.print("[bold cyan]Recommended Actions[/bold cyan]")
        self._console.print()

        for i, conflict in enumerate(critical_and_high, 1):
            severity_style = {
                Severity.CRITICAL: "bold red",
                Severity.HIGH: "bold yellow",
            }.get(conflict.severity, "yellow")

            self._console.print(
                f"[{severity_style}]{i}. {conflict.dns_name}[/{severity_style}] "
                f"[dim]on {conflict.network}[/dim]"
            )

            if conflict.remediation:
                for j, action in enumerate(conflict.remediation, 1):
                    self._console.print(f"   [dim]{j}.[/dim] {action}")

            self._console.print()

    def render_summary(self, report: ConflictReport) -> None:
        """Render a brief one-line summary."""
        if not report.has_conflicts:
            self._console.print("[green]OK[/green] - No conflicts detected")
        else:
            parts = []
            if report.critical_count > 0:
                parts.append(f"[bold red]{report.critical_count} critical[/bold red]")
            if report.high_count > 0:
                parts.append(f"[bold yellow]{report.high_count} high[/bold yellow]")
            if report.warning_count > 0:
                parts.append(f"[yellow]{report.warning_count} warning[/yellow]")

            self._console.print(f"[bold]Conflicts:[/bold] {', '.join(parts)}")
