"""Web dashboard for Docker network visualization."""

from __future__ import annotations

import os
from dataclasses import asdict
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, render_template

from netmon.conflicts import ConflictDetector, Severity
from netmon.docker_client import DockerClient
from netmon.scanner import NetworkScanner, get_all_dns_names


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
        refresh_interval = int(os.environ.get("NETMON_REFRESH_INTERVAL", "5"))
        return render_template("dashboard.html", refresh_interval=refresh_interval)

    @app.route("/api/topology")
    def api_topology() -> tuple[Any, int]:
        """Return network topology as JSON for vis.js."""
        try:
            client = DockerClient()
            scanner = NetworkScanner(client)
            detector = ConflictDetector()

            topology = scanner.scan()
            report = detector.analyze(topology)

            conflict_lookup = _build_conflict_lookup(report)

            nodes = []
            edges = []
            node_id = 0

            network_ids = {}
            for network_name in sorted(topology.networks.keys()):
                network_ids[network_name] = node_id
                nodes.append({
                    "id": node_id,
                    "label": network_name,
                    "group": "network",
                    "shape": "box",
                    "color": {"background": "#4a90d9", "border": "#2c5aa0"},
                    "font": {"color": "#ffffff"},
                })
                node_id += 1

            for network_name, network_nodes in topology.networks.items():
                for container in network_nodes:
                    dns_names = get_all_dns_names(container)
                    has_conflict = any(
                        (network_name, name) in conflict_lookup for name in dns_names
                    )

                    conflict_severity = None
                    if has_conflict:
                        for name in dns_names:
                            key = (network_name, name)
                            if key in conflict_lookup:
                                sev = conflict_lookup[key]
                                if conflict_severity is None or _severity_order(sev) < _severity_order(conflict_severity):
                                    conflict_severity = sev

                    color = _get_node_color(conflict_severity)

                    container_node_id = node_id
                    nodes.append({
                        "id": container_node_id,
                        "label": container.container_name,
                        "title": _build_tooltip(container, network_name, conflict_lookup),
                        "group": "container",
                        "shape": "ellipse",
                        "color": color,
                    })
                    node_id += 1

                    edges.append({
                        "from": network_ids[network_name],
                        "to": container_node_id,
                    })

            client.close()

            return jsonify({
                "nodes": nodes,
                "edges": edges,
            }), 200

        except Exception as e:
            return jsonify({"error": str(e)}), 500

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
                conflicts.append({
                    "network": conflict.network,
                    "dns_name": conflict.dns_name,
                    "severity": conflict.severity.value,
                    "containers": conflict.container_names,
                    "description": conflict.description,
                    "remediation": conflict.remediation,
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


def _get_node_color(severity: Severity | None) -> dict:
    """Get node color based on conflict severity."""
    if severity == Severity.CRITICAL:
        return {"background": "#dc3545", "border": "#a71d2a"}
    elif severity == Severity.HIGH:
        return {"background": "#fd7e14", "border": "#c96209"}
    elif severity == Severity.WARNING:
        return {"background": "#ffc107", "border": "#d39e00"}
    else:
        return {"background": "#28a745", "border": "#1e7e34"}


def _build_tooltip(container, network_name: str, conflict_lookup: dict) -> str:
    """Build HTML tooltip for a container node."""
    lines = [
        f"<b>{container.container_name}</b>",
        f"IP: {container.ip_address}",
    ]

    if container.service_name:
        lines.append(f"Service: {container.service_name}")

    if container.aliases:
        lines.append(f"Aliases: {', '.join(container.aliases)}")

    dns_names = get_all_dns_names(container)
    for name in dns_names:
        key = (network_name, name)
        if key in conflict_lookup:
            severity = conflict_lookup[key]
            lines.append(f"<span style='color: red'>Conflict: {name} ({severity.value})</span>")

    return "<br>".join(lines)


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
            dns_names = get_all_dns_names(container)
            conflicts = []
            for name in dns_names:
                key = (network_name, name)
                if key in conflict_lookup:
                    conflicts.append({
                        "name": name,
                        "severity": conflict_lookup[key].value,
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
