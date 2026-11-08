"""Phase 5: offline Docker containment command and configuration regressions."""

from __future__ import annotations

import pytest

from mcp_monitor.proxy.sandbox import OfflineDockerSandbox
from mcp_monitor.proxy.stdio_proxy import StdioMCPProxy

IMAGE_ID = "sha256:" + "a" * 64


def test_network_isolation_flags_are_immutable_and_no_shell_is_used() -> None:
    command = OfflineDockerSandbox(IMAGE_ID).build_command(["python", "-u", "/opt/mcp/server.py"])
    assert command[:4] == ["docker", "--host", "unix:///var/run/docker.sock", "run"]
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
    assert "--init" in command
    assert "--name" not in command


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
    assert proxy.command[:4] == ["docker", "--host", "unix:///var/run/docker.sock", "run"]
    assert "--name" in proxy.command
    assert proxy.command[proxy.command.index("--name") + 1].startswith("mcp-offline-")
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

@pytest.mark.parametrize("name", ["mcp-offline-123", "--network=host", "", "mcp-offline-" + "g" * 24])
def test_rejects_untrusted_container_names(name: str) -> None:
    with pytest.raises(ValueError, match="container name"):
        OfflineDockerSandbox(IMAGE_ID).build_command(["python"], container_name=name)


def test_independent_instances_use_distinct_cleanup_names() -> None:
    first = StdioMCPProxy(command=["python"], offline_sandbox=OfflineDockerSandbox(IMAGE_ID))
    second = StdioMCPProxy(command=["python"], offline_sandbox=OfflineDockerSandbox(IMAGE_ID))
    first_name = first.command[first.command.index("--name") + 1]
    second_name = second.command[second.command.index("--name") + 1]
    assert first_name != second_name
    assert first_name.startswith("mcp-offline-")
    assert len(first_name) == len(second_name)


def test_missing_docker_runtime_fails_without_unsandboxed_fallback(monkeypatch) -> None:
    import asyncio

    async def unavailable(*args, **kwargs):
        raise FileNotFoundError("synthetic Docker binary not installed")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", unavailable)
    proxy = StdioMCPProxy(command=["python"], offline_sandbox=OfflineDockerSandbox(IMAGE_ID))

    with pytest.raises(FileNotFoundError, match="synthetic Docker"):
        asyncio.run(proxy.start())
    assert proxy.command[0] == "docker"
