"""Network scanning and topology building."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from netmon.docker_client import ContainerInfo, DockerClient, NetworkInfo


class DnsNameSource(Enum):
    """Source of a DNS name for a container."""

    CONTAINER_NAME = "container name"
    SERVICE_NAME = "service name"
    ALIAS = "alias"


@dataclass
class DnsNameEntry:
    """A DNS name with its source."""

    name: str
    source: DnsNameSource
    container_name: str


@dataclass
class NetworkNode:
    """A container node in the network topology."""

    container_id: str
    container_name: str
    short_id: str
    ip_address: str
    aliases: list[str]
    service_name: str | None
    compose_project: str | None


@dataclass
class NetworkTopology:
    """Complete network topology of Docker environment."""

    networks: dict[str, list[NetworkNode]] = field(default_factory=dict)
    containers: dict[str, set[str]] = field(default_factory=dict)

    def add_container_to_network(
        self, network_name: str, container: ContainerInfo, ip_address: str, aliases: list[str]
    ) -> None:
        """Add a container to a network in the topology."""
        if network_name not in self.networks:
            self.networks[network_name] = []

        service_name = container.labels.get("com.docker.compose.service")
        compose_project = container.labels.get("com.docker.compose.project")

        node = NetworkNode(
            container_id=container.id,
            container_name=container.name,
            short_id=container.short_id,
            ip_address=ip_address,
            aliases=aliases,
            service_name=service_name,
            compose_project=compose_project,
        )

        self.networks[network_name].append(node)

        if container.name not in self.containers:
            self.containers[container.name] = set()
        self.containers[container.name].add(network_name)

    def get_networks_for_container(self, container_name: str) -> set[str]:
        """Get all networks a container is connected to."""
        return self.containers.get(container_name, set())


class NetworkScanner:
    """Scans Docker environment and builds network topology."""

    def __init__(self, client: DockerClient) -> None:
        self._client = client

    def scan(self, include_default_networks: bool = False) -> NetworkTopology:
        """Scan all networks and build topology.

        Args:
            include_default_networks: Include bridge, host, none networks
        """
        topology = NetworkTopology()
        networks = self._client.get_networks(include_default=include_default_networks)

        for network in networks:
            for container in network.containers:
                attachment = container.networks.get(network.name)
                if attachment:
                    topology.add_container_to_network(
                        network_name=network.name,
                        container=container,
                        ip_address=attachment.ip_address,
                        aliases=attachment.aliases,
                    )

        return topology

    def scan_network(self, network_name: str) -> NetworkTopology:
        """Scan a specific network."""
        topology = NetworkTopology()
        networks = self._client.get_networks(include_default=True)

        for network in networks:
            if network.name == network_name:
                for container in network.containers:
                    attachment = container.networks.get(network.name)
                    if attachment:
                        topology.add_container_to_network(
                            network_name=network.name,
                            container=container,
                            ip_address=attachment.ip_address,
                            aliases=attachment.aliases,
                        )
                break

        return topology


def get_all_dns_names(node: NetworkNode) -> list[str]:
    """Get all DNS names that can resolve to this container on a network.

    Docker DNS resolves:
    - Container name
    - Service name (if in compose)
    - Explicit network aliases
    """
    names = [node.container_name]

    if node.service_name:
        names.append(node.service_name)

    names.extend(node.aliases)

    return list(set(names))


def get_dns_name_entries(node: NetworkNode) -> list[DnsNameEntry]:
    """Get all DNS names with their sources for a container.

    Returns detailed information about each DNS name including its source type.
    """
    entries = []
    seen_names = set()

    # Container name is always a DNS name
    entries.append(DnsNameEntry(
        name=node.container_name,
        source=DnsNameSource.CONTAINER_NAME,
        container_name=node.container_name,
    ))
    seen_names.add(node.container_name)

    # Service name (from docker-compose)
    if node.service_name and node.service_name not in seen_names:
        entries.append(DnsNameEntry(
            name=node.service_name,
            source=DnsNameSource.SERVICE_NAME,
            container_name=node.container_name,
        ))
        seen_names.add(node.service_name)

    # Explicit network aliases
    for alias in node.aliases:
        if alias not in seen_names:
            entries.append(DnsNameEntry(
                name=alias,
                source=DnsNameSource.ALIAS,
                container_name=node.container_name,
            ))
            seen_names.add(alias)

    return entries
