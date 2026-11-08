"""Operator-enforced, offline Docker containment for downstream MCP stdio servers.

This opt-in profile blocks container network interfaces beyond loopback and
removes privileges. It does not confine the gateway host or the Docker daemon,
guarantee side-effect rollback, or provide an authenticated identity provider.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Sequence


# A content-addressed, preloaded Docker image ID or repository digest is required.
# This prevents mutable image tags or implicit pulls from changing the target.
_PINNED_IMAGE = re.compile(r"(?:[a-zA-Z0-9][a-zA-Z0-9._:/-]*@)?sha256:[a-f0-9]{64}\Z")


@dataclass(frozen=True)
class OfflineDockerSandbox:
    """Constrain a trusted operator's subprocess to a network-none container.

    No network, host volume, host PID namespace, privileged, or Docker-socket
    escape flags can be supplied by agent arguments. Untrusted agent-controlled
    values must never be used as this operator configuration.
    """

    image: str

    def __post_init__(self) -> None:
        if not isinstance(self.image, str) or not _PINNED_IMAGE.fullmatch(self.image):
            raise ValueError("Docker sandbox image must be a pinned sha256 image ID or digest")

    def build_command(self, server_command: Sequence[str]) -> list[str]:
        """Build a shell-free Docker command using the preloaded pinned image."""
        if (
            not isinstance(server_command, list | tuple)
            or not server_command
            or any(
                not isinstance(arg, str) or not arg or "\x00" in arg
                for arg in server_command
            )
        ):
            raise ValueError("Sandboxed server command must contain safe non-empty arguments")

        return [
            "docker",
            "run",
            "--rm",
            "-i",
            "--pull=never",
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--ipc=none",
            "--user=65534:65534",
            "--pids-limit=64",
            "--memory=256m",
            "--cpus=1",
            "--tmpfs=/tmp:rw,nosuid,nodev,size=16m",
            "--workdir=/tmp",
            self.image,
            *server_command,
        ]
