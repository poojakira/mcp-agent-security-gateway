"""Free-runner integration tests for an actual Docker network-none sandbox.

The image is constructed from disposable fixture source. Only IANA TEST-NET
addresses are probed; the sandbox has no network adapter beyond loopback.
"""

from __future__ import annotations

import asyncio
import json
import os

import pytest

from mcp_monitor.proxy.sandbox import OfflineDockerSandbox
from mcp_monitor.proxy.stdio_proxy import StdioMCPProxy

IMAGE_ID = os.environ.get("PHASE5_TEST_IMAGE_ID")
pytestmark = pytest.mark.skipif(not IMAGE_ID, reason="Offline image ID not supplied by Phase 5 CI")


async def call(proxy: StdioMCPProxy, kind: str, request_id: int) -> dict:
    message = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": "sandbox_probe", "arguments": {"kind": kind}},
    }
    raw = await asyncio.wait_for(proxy.handle_message(json.dumps(message).encode()), timeout=10.0)
    response = json.loads(raw)
    assert response["id"] == request_id
    assert "error" not in response, response
    return response["result"]


def test_actual_offline_network_and_filesystem_isolation() -> None:
    async def scenario() -> None:
        proxy = StdioMCPProxy(
            command=["python", "-u", "/opt/phase5/server.py"],
            offline_sandbox=OfflineDockerSandbox(IMAGE_ID),
        )
        await asyncio.wait_for(proxy.start(), timeout=10.0)
        try:
            ready = await call(proxy, "ready", 1)
            network = await call(proxy, "network", 2)
            filesystem = await call(proxy, "filesystem", 3)
        finally:
            await asyncio.wait_for(proxy.stop(), timeout=12.0)
        assert ready == {"status": "ready", "uid": 65534}
        assert network["network_denied"] is True
        assert network["socket_error"] != 0
        assert network["uid"] == 65534
        assert set(network["interfaces"]) <= {"lo"}
        assert filesystem["root_read_only"] is True
        assert filesystem["uid"] == 65534

    asyncio.run(scenario())
