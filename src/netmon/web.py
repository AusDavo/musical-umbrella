"""Web dashboard for Docker network monitoring."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from flask import Flask, jsonify, render_template

from netmon.conflicts import ConflictDetector, Severity
from netmon.docker_client import DockerClient
from netmon.scanner import NetworkScanner, get_dns_name_entries


def create_app() -> Flask:
    """Create and configure the Flask application."""
    template_dir = Path(__file__).parent / "templates"
    static_dir = Path(__file__).parent / "static"

    app = Flask(
        __name__,
        template_folder=str(template_dir),
        static_folder=str(static_dir),
    )

    @app.route("/")
    def dashboard() -> str:
        """Render the main dashboard."""
        return render_template("dashboard.html")

    @app.route("/api/conflicts")
    def api_conflicts() -> tuple[Any, int]:
        """Return conflict report as JSON."""
        try:
            client = DockerClient()
            scanner = NetworkScanner(client)
            detector = ConflictDetector()

            topology = scanner.scan()
            report = detector.analyze(topology)

            conflicts = []
            for conflict in report.conflicts:
                conflicting_names = [
                    {"container": cn.container_name, "source": cn.source}
                    for cn in conflict.conflicting_names
                ]
                conflicts.append({
                    "network": conflict.network,
                    "dns_name": conflict.dns_name,
                    "severity": conflict.severity.value,
                    "containers": conflict.container_names,
                    "description": conflict.description,
                    "remediation": conflict.remediation,
                    "conflicting_names": conflicting_names,
                })

            tree_data = _build_tree_data(topology, report)

            client.close()

            return jsonify({
                "summary": {
                    "total_networks": report.total_networks,
                    "total_containers": report.total_containers,
                    "total_conflicts": len(report.conflicts),
                    "critical_count": report.critical_count,
                    "high_count": report.high_count,
                    "warning_count": report.warning_count,
                },
                "conflicts": conflicts,
                "tree": tree_data,
            }), 200

        except Exception as e:
            return jsonify({"error": str(e)}), 500

    return app


def _build_conflict_lookup(report) -> dict[tuple[str, str], Severity]:
    """Build a lookup of (network, dns_name) -> severity."""
    lookup = {}
    for conflict in report.conflicts:
        key = (conflict.network, conflict.dns_name)
        if key not in lookup or _severity_order(conflict.severity) < _severity_order(lookup[key]):
            lookup[key] = conflict.severity
    return lookup


def _severity_order(severity: Severity) -> int:
    """Return sort order for severity (lower = more severe)."""
    return {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.WARNING: 2,
    }.get(severity, 3)


def _build_tree_data(topology, report) -> list[dict]:
    """Build tree structure for HTML tree view."""
    conflict_lookup = _build_conflict_lookup(report)
    tree = []

    for network_name in sorted(topology.networks.keys()):
        nodes = topology.networks[network_name]
        network_data = {
            "name": network_name,
            "type": "network",
            "containers": [],
        }

        for container in sorted(nodes, key=lambda n: n.container_name):
            dns_entries = get_dns_name_entries(container)
            conflicts = []
            for entry in dns_entries:
                key = (network_name, entry.name)
                if key in conflict_lookup:
                    conflicts.append({
                        "name": entry.name,
                        "severity": conflict_lookup[key].value,
                        "source": entry.source.value,
                    })

            container_data = {
                "name": container.container_name,
                "ip": container.ip_address,
                "service": container.service_name,
                "aliases": container.aliases,
                "conflicts": conflicts,
            }
            network_data["containers"].append(container_data)

        tree.append(network_data)

    return tree


def run_server(host: str = "0.0.0.0", port: int = 8080, debug: bool = False) -> None:
    """Run the Flask development server."""
    app = create_app()
    app.run(host=host, port=port, debug=debug, threaded=True)
