"""Operator-provisioned, no-network Docker sandbox for one protected MCP manifest.

This deliberately does not accept agent-selected mounts, paths, images, or
authorization. It is a disposable research adapter, not a general Docker API.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

from mcp_monitor.proxy.sandbox import OfflineDockerSandbox

_ALLOWED_HOST_PATH = re.compile(r"/[A-Za-z0-9/_.-]+\Z")
_SERVER_COMMAND = ("python", "-m", "mcp_monitor.protected_repo_server")


@dataclass(frozen=True)
class ProtectedRepoDockerSandbox(OfflineDockerSandbox):
    """Expose only the dedicated manifest directory to a no-network subprocess."""

    workspace: Path
    approved_updates: dict[str, str]
    host_uid: int
    host_gid: int

    def __post_init__(self) -> None:
        super().__post_init__()
        if (
            not isinstance(self.host_uid, int)
            or isinstance(self.host_uid, bool)
            or self.host_uid <= 0
            or not isinstance(self.host_gid, int)
            or isinstance(self.host_gid, bool)
            or self.host_gid <= 0
        ):
            raise ValueError("The sandbox requires a non-root operator UID/GID")
        if (
            not isinstance(self.approved_updates, dict)
            or not self.approved_updates
            or any(
                not isinstance(key, str) or not key or not isinstance(value, str) or not value
                for key, value in self.approved_updates.items()
            )
        ):
            raise ValueError("Explicit operator-approved package/version mapping required")
        self._verify_workspace()

    def _verify_workspace(self) -> None:
        root = self.workspace
        if not isinstance(root, Path) or not root.is_absolute():
            raise ValueError("Operator workspace must be an absolute Path")
        if not root.is_dir() or root.is_symlink() or root.resolve(strict=True) != root:
            raise ValueError("Operator workspace must be an existing non-symlink directory")
        if not _ALLOWED_HOST_PATH.fullmatch(str(root)):
            raise ValueError("Unsafe host workspace path")
        if root == Path("/") or len(root.parts) < 3:
            raise ValueError("Refusing overly broad host filesystem mount")
        if {entry.name for entry in root.iterdir()} != {"package.json"}:
            raise ValueError("Dedicated workspace must contain only package.json")
        manifest = root / "package.json"
        if (
            manifest.is_symlink()
            or not manifest.is_file()
            or os.stat(manifest, follow_symlinks=False).st_nlink != 1
        ):
            raise ValueError("Manifest must be a regular, single-link file")

    def build_command(
        self, server_command: list[str] | tuple[str, ...], *, container_name: str | None = None
    ) -> list[str]:
        if tuple(server_command) != _SERVER_COMMAND:
            raise ValueError("Protected sandbox only runs the pinned first-party MCP module")
        self._verify_workspace()
        base = super().build_command(server_command, container_name=container_name)
        base[base.index("--user=65534:65534")] = f"--user={self.host_uid}:{self.host_gid}"
        image_index = base.index(self.image)
        trusted_arguments = [
            "--mount",
            f"type=bind,source={self.workspace},target=/workspace",
            "--env",
            "MCP_PROTECTED_REPO_ROOT=/workspace",
            "--env",
            "MCP_APPROVED_DEPENDENCY_UPDATES="
            + json.dumps(self.approved_updates, sort_keys=True, separators=(",", ":")),
        ]
        return [*base[:image_index], *trusted_arguments, *base[image_index:]]
