"""Phase 5: offline Docker containment command and configuration regressions."""

from __future__ import annotations

import pytest

from mcp_monitor.proxy.sandbox import OfflineDockerSandbox
from mcp_monitor.proxy.stdio_proxy import StdioMCPProxy

IMAGE_ID = "sha256:" + "a" * 64


def test_network_isolation_flags_are_immutable_and_no_shell_is_used() -> None:
    command = OfflineDockerSandbox(IMAGE_ID).build_command(
        ["python", "-u", "/opt/mcp/server.py"]
    )
    assert command[:2] == ["docker", "run"]
    assert command[command.index("--workdir=/tmp") + 1] == IMAGE_ID
    assert command[-3:] == ["python", "-u", "/opt/mcp/server.py"]
    for option in (
        "--network=none",
        "--pull=never",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--ipc=none",
        "--user=65534:65534",
        "--pids-limit=64",
        "--memory=256m",
    ):
        assert option in command
    assert "--privileged" not in command
    assert "--network=host" not in command
    assert "--volume" not in command
    assert "--mount" not in command
    assert command[0] != "sh"


@pytest.mark.parametrize(
    "image",
    [
        "python:3.12-alpine",
        "latest",
        "--network=host",
        "example.invalid/image:latest",
        "sha256:not-a-digest",
        "sha256:" + "z" * 64,
        "sha256:" + "a" * 63,
        "sha256:" + "a" * 64 + " extra",
        "",
        None,
        False,
    ],
)
def test_unpinned_or_malformed_images_are_rejected(image: object) -> None:
    with pytest.raises(ValueError, match="pinned"):
        OfflineDockerSandbox(image)


@pytest.mark.parametrize(
    "command",
    [
        [],
        ["python", ""],
        ["python", "bad\x00arg"],
        ["python", None],
        "python -u server.py",
        None,
    ],
)
def test_invalid_sandbox_command_is_rejected(command: object) -> None:
    with pytest.raises(ValueError, match="server command"):
        OfflineDockerSandbox(IMAGE_ID).build_command(command)


def test_pinned_repository_digest_is_accepted() -> None:
    image = "registry.example:5000/team/mcp@sha256:" + "a" * 64
    assert OfflineDockerSandbox(image).build_command(["/app/mcp"])[-2:] == [
        image,
        "/app/mcp",
    ]


def test_proxy_uses_sandbox_command_without_implicit_fallback() -> None:
    proxy = StdioMCPProxy(
        command=["python", "-u", "/opt/mcp/server.py"],
        offline_sandbox=OfflineDockerSandbox(IMAGE_ID),
    )
    assert proxy.command[0:2] == ["docker", "run"]
    assert "--network=none" in proxy.command
    assert proxy.command[-4:] == [IMAGE_ID, "python", "-u", "/opt/mcp/server.py"]


def test_injected_transport_cannot_bypass_requested_sandbox() -> None:
    with pytest.raises(ValueError, match="Cannot override"):
        StdioMCPProxy(
            command=["python", "-u", "/opt/mcp/server.py"],
            offline_sandbox=OfflineDockerSandbox(IMAGE_ID),
            transport=object(),
        )


def test_invalid_sandbox_type_denied_during_setup() -> None:
    with pytest.raises(ValueError, match="offline_sandbox"):
        StdioMCPProxy(command=["python"], offline_sandbox={"image": IMAGE_ID})
