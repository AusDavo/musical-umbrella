"""Conflict detection for Docker network DNS names."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

from netmon.scanner import DnsNameSource, get_all_dns_names, get_dns_name_entries

if TYPE_CHECKING:
    from netmon.scanner import DnsNameEntry, NetworkNode, NetworkTopology


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
class ConflictingName:
    """Details about a name involved in a conflict."""

    container_name: str
    source: str  # "container name", "service name", or "alias"


@dataclass
class Conflict:
    """A detected DNS naming conflict."""

    network: str
    dns_name: str
    severity: Severity
    containers: list[NetworkNode]
    description: str
    remediation: list[str]
    conflicting_names: list[ConflictingName] = field(default_factory=list)

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

        # Map DNS name -> list of (node, DnsNameEntry)
        dns_name_to_entries: dict[str, list[tuple[NetworkNode, DnsNameEntry]]] = {}

        for node in nodes:
            for entry in get_dns_name_entries(node):
                if entry.name not in dns_name_to_entries:
                    dns_name_to_entries[entry.name] = []
                dns_name_to_entries[entry.name].append((node, entry))

        for dns_name, entries in dns_name_to_entries.items():
            if len(entries) > 1:
                unique_containers = {node.container_id for node, _ in entries}
                if len(unique_containers) > 1:
                    conflicts.append(
                        self._create_duplicate_conflict(network_name, dns_name, entries)
                    )

        if self._warn_generic and len(nodes) > 1:
            for node in nodes:
                for entry in get_dns_name_entries(node):
                    if entry.name.lower() in GENERIC_NAMES:
                        existing = [
                            c for c in conflicts if c.dns_name == entry.name and c.network == network_name
                        ]
                        if not existing:
                            conflicts.append(
                                self._create_generic_name_warning(network_name, entry, node)
                            )

        return conflicts

    def _create_duplicate_conflict(
        self, network: str, dns_name: str, entries: list[tuple[NetworkNode, DnsNameEntry]]
    ) -> Conflict:
        """Create a conflict for duplicate DNS names."""
        # Get unique nodes
        unique_nodes = []
        seen_ids = set()
        for node, _ in entries:
            if node.container_id not in seen_ids:
                unique_nodes.append(node)
                seen_ids.add(node.container_id)

        # Build detailed conflicting names list
        conflicting_names = []
        seen_container_ids = set()
        for node, entry in entries:
            if node.container_id not in seen_container_ids:
                conflicting_names.append(ConflictingName(
                    container_name=node.container_name,
                    source=entry.source.value,
                ))
                seen_container_ids.add(node.container_id)

        # Determine severity based on source types
        sources = {entry.source for _, entry in entries}
        is_exact_name_match = all(node.container_name == dns_name for node in unique_nodes)

        if is_exact_name_match:
            severity = Severity.CRITICAL
        else:
            severity = Severity.HIGH

        # Build detailed description showing sources
        source_descriptions = []
        for node, entry in entries:
            if node.container_id in {n.container_id for n in unique_nodes}:
                source_descriptions.append(f"'{node.container_name}' ({entry.source.value})")

        # Remove duplicates while preserving order
        seen_desc = set()
        unique_source_descriptions = []
        for desc in source_descriptions:
            if desc not in seen_desc:
                unique_source_descriptions.append(desc)
                seen_desc.add(desc)

        description = (
            f"DNS name '{dns_name}' resolves to multiple containers: "
            f"{', '.join(unique_source_descriptions)}"
        )

        remediation = self._get_duplicate_remediation(network, dns_name, unique_nodes, sources)

        return Conflict(
            network=network,
            dns_name=dns_name,
            severity=severity,
            containers=unique_nodes,
            description=description,
            remediation=remediation,
            conflicting_names=conflicting_names,
        )

    def _get_duplicate_remediation(
        self, network: str, dns_name: str, nodes: list[NetworkNode], sources: set[DnsNameSource]
    ) -> list[str]:
        """Generate remediation strategies for duplicate DNS conflicts."""
        remediation = []

        projects = {n.compose_project for n in nodes if n.compose_project}

        # Specific advice based on source types
        if DnsNameSource.SERVICE_NAME in sources:
            remediation.append(
                f"Service name conflict: Rename the 'service:' key in one of the compose files "
                f"(e.g., '{dns_name}' -> 'myproject-{dns_name}')."
            )

        if DnsNameSource.ALIAS in sources:
            remediation.append(
                f"Alias conflict: Remove or rename the network alias in docker-compose.yml. "
                f"Check the 'networks:<network>:aliases:' section."
            )

        if DnsNameSource.CONTAINER_NAME in sources:
            remediation.append(
                f"Container name conflict: Use 'container_name:' in docker-compose.yml "
                f"to set unique container names, or rename the service."
            )

        if len(projects) > 1:
            remediation.append(
                f"Isolate stacks: Move each stack to its own network instead of sharing '{network}'. "
                f"Only connect services that need external access to the shared network."
            )

        if dns_name.lower() in GENERIC_NAMES:
            remediation.append(
                f"Use stack-prefixed names for common services "
                f"(e.g., 'immich-{dns_name}', 'seafile-{dns_name}' instead of just '{dns_name}')."
            )

        return remediation

    def _create_generic_name_warning(
        self, network: str, entry: DnsNameEntry, node: NetworkNode
    ) -> Conflict:
        """Create a warning for generic names on shared networks."""
        dns_name = entry.name
        source_type = entry.source.value

        description = (
            f"Container '{node.container_name}' uses generic DNS name '{dns_name}' "
            f"(via {source_type}) on shared network '{network}'. This may cause "
            f"confusion if another stack with the same name joins this network."
        )

        project_prefix = node.compose_project or "myapp"
        suggested_name = f"{project_prefix}-{dns_name}"

        remediation = []

        if entry.source == DnsNameSource.SERVICE_NAME:
            remediation.append(
                f"Rename the service in docker-compose.yml "
                f"(e.g., '{dns_name}' -> '{suggested_name}')."
            )
        elif entry.source == DnsNameSource.ALIAS:
            remediation.append(
                f"Remove or rename the alias '{dns_name}' in the networks section "
                f"of docker-compose.yml."
            )
        else:
            remediation.append(
                f"Set a unique container_name in docker-compose.yml "
                f"(e.g., container_name: '{suggested_name}')."
            )

        remediation.append(
            f"Keep '{node.container_name}' on an isolated network and only expose "
            f"the application container to '{network}'."
        )

        conflicting_names = [ConflictingName(
            container_name=node.container_name,
            source=source_type,
        )]

        return Conflict(
            network=network,
            dns_name=dns_name,
            severity=Severity.WARNING,
            containers=[node],
            description=description,
            remediation=remediation,
            conflicting_names=conflicting_names,
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
