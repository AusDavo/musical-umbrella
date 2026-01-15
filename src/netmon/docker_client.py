"""Docker SDK wrapper for network and container queries."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import docker
from docker.errors import DockerException

if TYPE_CHECKING:
    from collections.abc import Generator

    from docker.models.containers import Container
    from docker.models.networks import Network


@dataclass
class ContainerInfo:
    """Simplified container information for network analysis."""

    id: str
    name: str
    short_id: str
    labels: dict[str, str]
    networks: dict[str, NetworkAttachment]


@dataclass
class NetworkAttachment:
    """Container's attachment to a specific network."""

    network_id: str
    network_name: str
    ip_address: str
    aliases: list[str]


@dataclass
class NetworkInfo:
    """Simplified network information."""

    id: str
    name: str
    driver: str
    scope: str
    containers: list[ContainerInfo]


class DockerClient:
    """Wrapper around Docker SDK for network monitoring."""

    def __init__(self) -> None:
        try:
            self._client = docker.from_env()
            self._client.ping()
        except DockerException as e:
            raise ConnectionError(f"Failed to connect to Docker: {e}") from e

    def get_networks(self, include_default: bool = False) -> list[NetworkInfo]:
        """Get all Docker networks with their connected containers.

        Args:
            include_default: Include default networks (bridge, host, none)
        """
        default_networks = {"bridge", "host", "none"}
        networks: list[Network] = self._client.networks.list()

        result = []
        for network in networks:
            if not include_default and network.name in default_networks:
                continue

            network.reload()
            containers = self._get_containers_on_network(network)

            result.append(
                NetworkInfo(
                    id=network.id,
                    name=network.name,
                    driver=network.attrs.get("Driver", "unknown"),
                    scope=network.attrs.get("Scope", "unknown"),
                    containers=containers,
                )
            )

        return result

    def _get_containers_on_network(self, network: Network) -> list[ContainerInfo]:
        """Extract container information from a network."""
        containers = []
        network_containers = network.attrs.get("Containers", {})

        for container_id, container_data in network_containers.items():
            try:
                container: Container = self._client.containers.get(container_id)
                container_info = self._build_container_info(container, network, container_data)
                containers.append(container_info)
            except docker.errors.NotFound:
                continue

        return containers

    def _build_container_info(
        self, container: Container, network: Network, network_data: dict
    ) -> ContainerInfo:
        """Build ContainerInfo from container and network data."""
        container_networks = {}

        for net_name, net_config in container.attrs.get("NetworkSettings", {}).get(
            "Networks", {}
        ).items():
            aliases = net_config.get("Aliases", []) or []
            container_networks[net_name] = NetworkAttachment(
                network_id=net_config.get("NetworkID", ""),
                network_name=net_name,
                ip_address=net_config.get("IPAddress", ""),
                aliases=[a for a in aliases if a != container.id[:12]],
            )

        return ContainerInfo(
            id=container.id,
            name=container.name,
            short_id=container.short_id,
            labels=container.labels or {},
            networks=container_networks,
        )

    def get_all_containers(self) -> list[ContainerInfo]:
        """Get all running containers with their network information."""
        containers: list[Container] = self._client.containers.list()
        result = []

        for container in containers:
            container_networks = {}

            for net_name, net_config in container.attrs.get("NetworkSettings", {}).get(
                "Networks", {}
            ).items():
                aliases = net_config.get("Aliases", []) or []
                container_networks[net_name] = NetworkAttachment(
                    network_id=net_config.get("NetworkID", ""),
                    network_name=net_name,
                    ip_address=net_config.get("IPAddress", ""),
                    aliases=[a for a in aliases if a != container.id[:12]],
                )

            result.append(
                ContainerInfo(
                    id=container.id,
                    name=container.name,
                    short_id=container.short_id,
                    labels=container.labels or {},
                    networks=container_networks,
                )
            )

        return result

    def watch_events(self) -> Generator[dict, None, None]:
        """Watch Docker events for container and network changes."""
        event_filters = {
            "type": ["container", "network"],
            "event": ["start", "stop", "die", "connect", "disconnect"],
        }

        for event in self._client.events(decode=True, filters=event_filters):
            yield event

    def close(self) -> None:
        """Close the Docker client connection."""
        self._client.close()
