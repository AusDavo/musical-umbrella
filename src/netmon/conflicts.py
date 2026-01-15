"""Conflict detection for Docker network DNS names."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from netmon.scanner import get_all_dns_names

if TYPE_CHECKING:
    from netmon.scanner import NetworkNode, NetworkTopology


class Severity(Enum):
    """Conflict severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    WARNING = "warning"


GENERIC_NAMES = frozenset(
    {
        "db",
        "database",
        "postgres",
        "postgresql",
        "mysql",
        "mariadb",
        "mongo",
        "mongodb",
        "redis",
        "cache",
        "memcached",
        "elasticsearch",
        "es",
        "rabbitmq",
        "mq",
        "kafka",
        "zookeeper",
        "api",
        "app",
        "web",
        "backend",
        "frontend",
        "worker",
        "nginx",
        "proxy",
        "traefik",
        "caddy",
    }
)


@dataclass
class Conflict:
    """A detected DNS naming conflict."""

    network: str
    dns_name: str
    severity: Severity
    containers: list[NetworkNode]
    description: str
    remediation: list[str]

    @property
    def container_names(self) -> list[str]:
        """Get the names of conflicting containers."""
        return [c.container_name for c in self.containers]


@dataclass
class ConflictReport:
    """Complete conflict analysis report."""

    conflicts: list[Conflict]
    total_networks: int
    total_containers: int

    @property
    def critical_count(self) -> int:
        return sum(1 for c in self.conflicts if c.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for c in self.conflicts if c.severity == Severity.HIGH)

    @property
    def warning_count(self) -> int:
        return sum(1 for c in self.conflicts if c.severity == Severity.WARNING)

    @property
    def has_conflicts(self) -> bool:
        return len(self.conflicts) > 0


class ConflictDetector:
    """Detects DNS naming conflicts in Docker networks."""

    def __init__(self, warn_generic_names: bool = True) -> None:
        """Initialize the detector.

        Args:
            warn_generic_names: Warn about generic names like 'db', 'redis' on shared networks
        """
        self._warn_generic = warn_generic_names

    def analyze(self, topology: NetworkTopology) -> ConflictReport:
        """Analyze topology for conflicts."""
        conflicts = []

        for network_name, nodes in topology.networks.items():
            conflicts.extend(self._check_network(network_name, nodes))

        total_containers = len(
            {node.container_id for nodes in topology.networks.values() for node in nodes}
        )

        return ConflictReport(
            conflicts=conflicts,
            total_networks=len(topology.networks),
            total_containers=total_containers,
        )

    def _check_network(self, network_name: str, nodes: list[NetworkNode]) -> list[Conflict]:
        """Check a single network for conflicts."""
        conflicts = []

        dns_name_to_nodes: dict[str, list[NetworkNode]] = {}

        for node in nodes:
            for dns_name in get_all_dns_names(node):
                if dns_name not in dns_name_to_nodes:
                    dns_name_to_nodes[dns_name] = []
                dns_name_to_nodes[dns_name].append(node)

        for dns_name, matching_nodes in dns_name_to_nodes.items():
            if len(matching_nodes) > 1:
                unique_containers = {n.container_id for n in matching_nodes}
                if len(unique_containers) > 1:
                    conflicts.append(
                        self._create_duplicate_conflict(network_name, dns_name, matching_nodes)
                    )

        if self._warn_generic and len(nodes) > 1:
            for node in nodes:
                for dns_name in get_all_dns_names(node):
                    if dns_name.lower() in GENERIC_NAMES:
                        existing = [
                            c for c in conflicts if c.dns_name == dns_name and c.network == network_name
                        ]
                        if not existing:
                            conflicts.append(
                                self._create_generic_name_warning(network_name, dns_name, node)
                            )

        return conflicts

    def _create_duplicate_conflict(
        self, network: str, dns_name: str, nodes: list[NetworkNode]
    ) -> Conflict:
        """Create a conflict for duplicate DNS names."""
        unique_nodes = []
        seen_ids = set()
        for node in nodes:
            if node.container_id not in seen_ids:
                unique_nodes.append(node)
                seen_ids.add(node.container_id)

        is_exact_name_match = all(node.container_name == dns_name for node in unique_nodes)

        severity = Severity.CRITICAL if is_exact_name_match else Severity.HIGH

        container_list = ", ".join(n.container_name for n in unique_nodes)
        description = (
            f"DNS name '{dns_name}' resolves to multiple containers on network '{network}': "
            f"{container_list}"
        )

        remediation = self._get_duplicate_remediation(network, dns_name, unique_nodes)

        return Conflict(
            network=network,
            dns_name=dns_name,
            severity=severity,
            containers=unique_nodes,
            description=description,
            remediation=remediation,
        )

    def _get_duplicate_remediation(
        self, network: str, dns_name: str, nodes: list[NetworkNode]
    ) -> list[str]:
        """Generate remediation strategies for duplicate DNS conflicts."""
        remediation = []

        projects = {n.compose_project for n in nodes if n.compose_project}

        if len(projects) > 1:
            remediation.append(
                f"Move each stack to its own isolated network instead of sharing '{network}'. "
                f"Only connect services that need external access to the shared network."
            )

        remediation.append(
            f"Rename the service in one of the compose files to use a unique name "
            f"(e.g., '{dns_name}' -> 'myapp-{dns_name}')."
        )

        remediation.append(
            f"Use explicit network aliases in docker-compose.yml to give each service "
            f"a unique DNS name on the shared network."
        )

        if dns_name.lower() in GENERIC_NAMES:
            remediation.append(
                f"Consider using stack-prefixed names for common services "
                f"(e.g., 'immich-db', 'seafile-db' instead of just 'db')."
            )

        return remediation

    def _create_generic_name_warning(
        self, network: str, dns_name: str, node: NetworkNode
    ) -> Conflict:
        """Create a warning for generic names on shared networks."""
        description = (
            f"Container '{node.container_name}' uses generic DNS name '{dns_name}' "
            f"on shared network '{network}'. This may cause confusion if another "
            f"stack with the same service name joins this network."
        )

        project_prefix = node.compose_project or "myapp"
        suggested_name = f"{project_prefix}-{dns_name}"

        remediation = [
            f"Rename the service to include a project prefix (e.g., '{suggested_name}').",
            f"Keep '{node.container_name}' on an isolated network and only expose "
            f"the application container to '{network}'.",
            f"Use an explicit network alias in docker-compose.yml to override the "
            f"DNS name on the shared network.",
        ]

        return Conflict(
            network=network,
            dns_name=dns_name,
            severity=Severity.WARNING,
            containers=[node],
            description=description,
            remediation=remediation,
        )


def find_cross_network_conflicts(topology: NetworkTopology) -> list[tuple[str, list[str]]]:
    """Find containers with the same name on multiple networks.

    This isn't necessarily a conflict, but can indicate potential issues
    if those networks get connected.

    Returns:
        List of (container_name, networks) tuples
    """
    multi_network_containers = []

    for container_name, networks in topology.containers.items():
        if len(networks) > 1:
            multi_network_containers.append((container_name, sorted(networks)))

    return multi_network_containers
