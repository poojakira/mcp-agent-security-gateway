"""Attested Docker --internal bridge boundary for an MCP stdio server.

The operator provisions a dedicated Docker network with exactly one trusted
proxy sidecar attached. The gateway attests the network immediately before
launching the MCP server. It does not attest the proxy's egress policy.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from mcp_monitor.proxy.sandbox import OfflineDockerSandbox

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_PROXY_NAME = re.compile(r"mcp-egress-[a-z0-9][a-z0-9-]{0,47}\Z")


@dataclass(frozen=True)
class InternalDockerSandbox:
    """Immutable operator-owned network and proxy identities."""

    image: str
    network_id: str
    proxy_container_id: str
    proxy_name: str
    proxy_port: int = 3128

    def __post_init__(self) -> None:
        OfflineDockerSandbox(self.image)
        for label, value in (
            ("network_id", self.network_id),
            ("proxy_container_id", self.proxy_container_id),
        ):
            if not isinstance(value, str) or not _HEX64.fullmatch(value):
                raise ValueError(f"{label} must be a full immutable Docker ID")
        if not isinstance(self.proxy_name, str) or not _PROXY_NAME.fullmatch(self.proxy_name):
            raise ValueError("proxy_name must identify a trusted mcp-egress- sidecar")
        if type(self.proxy_port) is not int or not 1 <= self.proxy_port <= 65535:
            raise ValueError("Invalid trusted proxy port")

    @property
    def proxy_url(self) -> str:
        return f"http://{self.proxy_name}:{self.proxy_port}"

    def build_command(self, command: list[str], *, container_name: str) -> list[str]:
        """Preserve Phase 5 hardening; change only Docker network and proxy env."""
        base = OfflineDockerSandbox(self.image).build_command(
            command, container_name=container_name
        )
        base[base.index("--network=none")] = f"--network={self.network_id}"
        image_pos = base.index(self.image)
        env: list[str] = []
        for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
            env.extend(["--env", f"{key}={self.proxy_url}"])
        for key in ("NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy"):
            env.extend(["--env", f"{key}="])
        return [*base[:image_pos], *env, *base[image_pos:]]

    def validate_network_inspection(self, data: Any) -> None:
        """Fail closed unless a single correct proxy inhabits this bridge."""
        if not isinstance(data, dict) or (
            data.get("Id") != self.network_id
            or data.get("Internal") is not True
            or data.get("Driver") != "bridge"
            or data.get("EnableIPv6") is not False
            or data.get("Scope") != "local"
        ):
            raise RuntimeError("Trusted internal network attestation failed")
        members = data.get("Containers")
        if not isinstance(members, dict) or set(members) != {self.proxy_container_id}:
            raise RuntimeError("Internal network must contain only the trusted proxy")
        proxy = members[self.proxy_container_id]
        if not isinstance(proxy, dict) or proxy.get("Name") != self.proxy_name:
            raise RuntimeError("Internal egress proxy identity mismatch")
