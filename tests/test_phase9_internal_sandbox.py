"""Phase 9 restricted internal Docker network and exact sidecar identity checks."""

from __future__ import annotations

import asyncio
import json

import pytest

from mcp_monitor.proxy.internal_sandbox import InternalDockerSandbox
from mcp_monitor.proxy.stdio_proxy import InternalDockerTransport, StdioMCPProxy

IMAGE = "sha256:" + "a" * 64
NETWORK = "b" * 64
PROXY_ID = "c" * 64
PROXY_NAME = "mcp-egress-synthetic"


def sandbox() -> InternalDockerSandbox:
    return InternalDockerSandbox(
        IMAGE,
        NETWORK,
        PROXY_ID,
        PROXY_NAME,
    )


def inspection(**overrides) -> dict:
    data = {
        "Id": NETWORK,
        "Internal": True,
        "Driver": "bridge",
        "EnableIPv6": False,
        "Scope": "local",
        "Containers": {PROXY_ID: {"Name": PROXY_NAME}},
    }
    data.update(overrides)
    return data


def test_pinned_attested_network_and_proxy_env() -> None:
    gateway = StdioMCPProxy(
        command=["python", "-u", "/opt/phase9/mcp.py"], internal_sandbox=sandbox()
    )
    cmd = gateway.command
    assert cmd[:4] == ["docker", "--host", "unix:///var/run/docker.sock", "run"]
    assert f"--network={NETWORK}" in cmd
    assert "--network=host" not in cmd
    assert "--privileged" not in cmd
    assert "--pull=never" in cmd
    assert "--read-only" in cmd
    assert "--cap-drop=ALL" in cmd
    assert "--security-opt=no-new-privileges" in cmd
    assert "--user=65534:65534" in cmd
    assert "--mount" not in cmd
    assert "--volume" not in cmd
    assert "HTTPS_PROXY=http://" + PROXY_NAME + ":3128" in cmd
    assert "NO_PROXY=" in cmd
    assert cmd[-4:] == [IMAGE, "python", "-u", "/opt/phase9/mcp.py"]


@pytest.mark.parametrize(
    "overrides",
    [
        {"Internal": False},
        {"EnableIPv6": True},
        {"Driver": "overlay"},
        {"Scope": "swarm"},
        {"Id": "0" * 64},
        {"Containers": {}},
        {"Containers": {PROXY_ID: {"Name": PROXY_NAME}, "d" * 64: {"Name": "intruder"}}},
        {"Containers": {PROXY_ID: {"Name": "mcp-egress-spoofed"}}},
    ],
)
def test_invalid_network_state_denied(overrides: dict) -> None:
    with pytest.raises(RuntimeError):
        sandbox().validate_network_inspection(inspection(**overrides))


@pytest.mark.parametrize(
    "changes",
    [
        {"image": "latest"},
        {"network_id": "not-immutable"},
        {"proxy_container_id": "-not-id"},
        {"proxy_name": "evil-proxy"},
        {"proxy_name": "--network=host"},
        {"proxy_port": 0},
        {"proxy_port": True},
        {"proxy_port": 70000},
    ],
)
def test_rejects_untrusted_sandbox_configuration(changes: dict) -> None:
    args = {
        "image": IMAGE,
        "network_id": NETWORK,
        "proxy_container_id": PROXY_ID,
        "proxy_name": PROXY_NAME,
    }
    args.update(changes)
    with pytest.raises(ValueError):
        InternalDockerSandbox(**args)


def test_transport_bypass_and_conflicting_sandboxes_rejected() -> None:
    with pytest.raises(ValueError, match="override"):
        StdioMCPProxy(command=["python"], internal_sandbox=sandbox(), transport=object())
    from mcp_monitor.proxy.sandbox import OfflineDockerSandbox

    with pytest.raises(ValueError, match="cannot be combined"):
        StdioMCPProxy(
            command=["python"],
            internal_sandbox=sandbox(),
            offline_sandbox=OfflineDockerSandbox(IMAGE),
        )



def test_internal_transport_parent_constructor_preserves_container_identity() -> None:
    gateway = StdioMCPProxy(
        command=["python", "-u", "/opt/phase9/mcp.py"],
        internal_sandbox=sandbox(),
    )
    transport = gateway._transport
    assert isinstance(transport, InternalDockerTransport)
    assert transport._sandbox == sandbox()
    assert transport.container_name.startswith("mcp-offline-")
    assert len(transport.container_name) == len("mcp-offline-") + 24
    assert transport.command == gateway.command
    assert gateway.command.count(transport.container_name) == 1


def test_failed_attestation_never_starts_unrestricted_process(monkeypatch) -> None:
    async def scenario() -> None:
        gateway = StdioMCPProxy(command=["python"], internal_sandbox=sandbox())
        transport = gateway._transport
        assert isinstance(transport, InternalDockerTransport)
        launched = []

        async def inspect(*args):
            return 0, json.dumps(inspection(Internal=False)).encode()

        async def illegal_launch():
            launched.append(True)

        monkeypatch.setattr(transport, "_docker_call", inspect)
        monkeypatch.setattr(transport, "_process", None)
        monkeypatch.setattr(type(transport).__bases__[0], "start", illegal_launch)
        with pytest.raises(RuntimeError, match="attestation"):
            await gateway.start()
        assert launched == []

    asyncio.run(scenario())
