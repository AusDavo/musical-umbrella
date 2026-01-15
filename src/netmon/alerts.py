"""Alerting system for conflict notifications."""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from enum import Enum
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from netmon.conflicts import ConflictReport


class AlertType(Enum):
    """Supported alert backend types."""

    WEBHOOK = "webhook"
    NTFY = "ntfy"
    GOTIFY = "gotify"


class AlertBackend(ABC):
    """Base class for alert backends."""

    @abstractmethod
    def send(self, title: str, message: str, priority: str = "default") -> bool:
        """Send an alert.

        Args:
            title: Alert title
            message: Alert message body
            priority: Priority level (low, default, high, urgent)

        Returns:
            True if alert was sent successfully
        """
        ...


class WebhookBackend(AlertBackend):
    """Generic webhook alert backend."""

    def __init__(self, url: str) -> None:
        self._url = url

    def send(self, title: str, message: str, priority: str = "default") -> bool:
        try:
            response = httpx.post(
                self._url,
                json={
                    "title": title,
                    "message": message,
                    "priority": priority,
                },
                timeout=10.0,
            )
            return response.is_success
        except httpx.HTTPError:
            return False


class NtfyBackend(AlertBackend):
    """ntfy.sh alert backend."""

    PRIORITY_MAP = {
        "low": "2",
        "default": "3",
        "high": "4",
        "urgent": "5",
    }

    def __init__(self, url: str) -> None:
        self._url = url.rstrip("/")

    def send(self, title: str, message: str, priority: str = "default") -> bool:
        try:
            response = httpx.post(
                self._url,
                data=message.encode("utf-8"),
                headers={
                    "Title": title,
                    "Priority": self.PRIORITY_MAP.get(priority, "3"),
                    "Tags": "docker,network,warning",
                },
                timeout=10.0,
            )
            return response.is_success
        except httpx.HTTPError:
            return False


class GotifyBackend(AlertBackend):
    """Gotify alert backend."""

    PRIORITY_MAP = {
        "low": 2,
        "default": 5,
        "high": 7,
        "urgent": 10,
    }

    def __init__(self, url: str, token: str) -> None:
        self._url = url.rstrip("/")
        self._token = token

    def send(self, title: str, message: str, priority: str = "default") -> bool:
        try:
            response = httpx.post(
                f"{self._url}/message",
                params={"token": self._token},
                json={
                    "title": title,
                    "message": message,
                    "priority": self.PRIORITY_MAP.get(priority, 5),
                },
                timeout=10.0,
            )
            return response.is_success
        except httpx.HTTPError:
            return False


class AlertDispatcher:
    """Dispatches alerts through configured backends."""

    def __init__(self, backend: AlertBackend | None = None) -> None:
        self._backend = backend

    @classmethod
    def from_env(cls) -> AlertDispatcher:
        """Create dispatcher from environment variables.

        Environment variables:
            NETMON_ALERT_URL: Alert endpoint URL
            NETMON_ALERT_TYPE: Backend type (webhook, ntfy, gotify)
            NETMON_GOTIFY_TOKEN: Token for Gotify (required if type is gotify)
        """
        url = os.environ.get("NETMON_ALERT_URL")
        if not url:
            return cls(None)

        alert_type = os.environ.get("NETMON_ALERT_TYPE", "webhook").lower()

        backend: AlertBackend
        if alert_type == "ntfy":
            backend = NtfyBackend(url)
        elif alert_type == "gotify":
            token = os.environ.get("NETMON_GOTIFY_TOKEN", "")
            backend = GotifyBackend(url, token)
        else:
            backend = WebhookBackend(url)

        return cls(backend)

    @property
    def is_configured(self) -> bool:
        """Check if alerting is configured."""
        return self._backend is not None

    def send_conflict_alert(self, report: ConflictReport) -> bool:
        """Send an alert about detected conflicts."""
        if not self._backend or not report.has_conflicts:
            return False

        title = "Docker Network Conflicts Detected"

        lines = [f"Found {len(report.conflicts)} conflict(s):"]
        if report.critical_count > 0:
            lines.append(f"  - {report.critical_count} CRITICAL")
        if report.high_count > 0:
            lines.append(f"  - {report.high_count} HIGH")
        if report.warning_count > 0:
            lines.append(f"  - {report.warning_count} WARNING")

        lines.append("")
        lines.append("Top issues:")
        for conflict in report.conflicts[:5]:
            lines.append(f"  [{conflict.severity.value}] {conflict.dns_name} on {conflict.network}")

        message = "\n".join(lines)

        priority = "urgent" if report.critical_count > 0 else "high" if report.high_count > 0 else "default"

        return self._backend.send(title, message, priority)

    def send_test_alert(self) -> bool:
        """Send a test alert to verify configuration."""
        if not self._backend:
            return False

        return self._backend.send(
            title="Docker Network Monitor Test",
            message="This is a test alert from docker-netmon.",
            priority="low",
        )
