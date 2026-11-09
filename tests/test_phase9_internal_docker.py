"""Real disposable Docker --internal bridge and synthetic sidecar verification."""

from __future__ import annotations

import asyncio
import json
import os

import pytest

from mcp_monitor.proxy.internal_sandbox import InternalDockerSandbox
from mcp_monitor.proxy.stdio_proxy import StdioMCPProxy


IMAGE = os.environ.get("PHASE9_IMAGE_ID")
NETWORK = os.environ.get("PHASE9_NETWORK_ID")
PROXY = os.environ.get("PHASE9_PROXY_ID")
NAME = os.environ.get("PHASE9_PROXY_NAME")
pytestmark = pytest.mark.skipif(
    not all((IMAGE, NETWORK, PROXY, NAME)),
    reason="Phase 9 disposable Docker fixture was not provisioned",
)


async def call(gateway: StdioMCPProxy, kind: str, ident: int) -> dict:
    value = {
        "jsonrpc": "2.0",
        "id": ident,
        "method": "tools/call",
        "params": {"name": "phase9_probe", "arguments": {"kind": kind}},
    }
    raw = await asyncio.wait_for(
        gateway.handle_message(json.dumps(value).encode()), timeout=12
    )
    response = json.loads(raw)
    assert "error" not in response, response
    return response["result"]


def test_real_internal_bridge_only_talks_to_attested_sidecar() -> None:
    async def scenario() -> None:
        sandbox = InternalDockerSandbox(
            IMAGE, NETWORK, PROXY, NAME
        )
        gateway = StdioMCPProxy(
            command=["python", "-u", "/opt/phase9/mcp.py"],
            internal_sandbox=sandbox,
        )
        name = gateway._transport.container_name
        os.environ["PHASE9_SYNTHETIC_HOST_SECRET"] = "synthetic-not-for-production"
        await asyncio.wait_for(gateway.start(), timeout=15)
        try:
            ready = await call(gateway, "ready", 1)
            direct = await call(gateway, "direct", 2)
            via_sidecar = await call(gateway, "proxy", 3)
            filesystem = await call(gateway, "filesystem", 4)
            secret = await call(gateway, "secret", 5)
        finally:
            await asyncio.wait_for(gateway.stop(), timeout=15)
            os.environ.pop("PHASE9_SYNTHETIC_HOST_SECRET", None)
        assert ready["uid"] == 65534
        assert direct["direct_denied"] is True
        assert direct["socket_error"] != 0
        assert via_sidecar["proxy_reachable"] is True
        assert filesystem == {"root_write_denied": True, "uid": 65534}
        assert secret["host_secret_inherited"] is False
        process = await asyncio.create_subprocess_exec(
            "docker", "--host", "unix:///var/run/docker.sock",
            "ps", "--all", "--filter", f"name=^/{name}$",
            "--format", "{{.Names}}",
            stdout=asyncio.subprocess.PIPE,
        )
        output, _ = await process.communicate()
        assert process.returncode == 0
        assert output.strip() == b""

    asyncio.run(scenario())
