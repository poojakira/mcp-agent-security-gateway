"""Real MCP filesystem stdio server smoke test (isolated temporary directory).

Run only in an environment with Node.js 24+, npm/npx and network access.
This is separate from fake-transport tests and tests actual MCP I/O.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import tempfile
from pathlib import Path

import pytest

from mcp_monitor.policy.policy_engine import PolicyEngine
from mcp_monitor.proxy.stdio_proxy import StdioMCPProxy


def request(request_id, method, params=None):
    return json.dumps({
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
        "params": params or {},
    }).encode()


async def live_scenario(root: Path):
    testfile = root / "safe.txt"
    testfile.write_text("known-good-content", encoding="utf-8")

    # The policy marks write_file dangerous for this isolated test. The real
    # filesystem server supports write_file, allowing a meaningful side-effect
    # check that the gateway refuses it before it can change an actual file.
    policy = PolicyEngine(
        allowed_servers={"filesystem"},
        dangerous_tools={"write_file", "delete_file", "shell_exec"},
    )
    proxy = StdioMCPProxy(
        ["npx", "--yes", "@modelcontextprotocol/server-filesystem@2.0.1", str(root)],
        server_id="filesystem",
        policy_engine=policy,
    )
    await asyncio.wait_for(proxy.start(), timeout=120)
    try:
        init = await asyncio.wait_for(proxy.handle_message(request(
            1, "initialize", {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "security-gateway-smoke", "version": "1.0"},
            },
        )), timeout=120)
        parsed_init = json.loads(init)
        assert "result" in parsed_init, parsed_init
        print("REAL SERVER: initialization succeeded", flush=True)

        await asyncio.wait_for(proxy.handle_message(json.dumps({
            "jsonrpc": "2.0", "method": "notifications/initialized",
        }).encode()), timeout=30)

        good = await asyncio.wait_for(proxy.handle_message(request(
            2, "tools/call", {
                "name": "read_file", "arguments": {"path": str(testfile)},
            },
        )), timeout=60)
        parsed_good = json.loads(good)
        assert "result" in parsed_good, parsed_good
        assert "known-good-content" in json.dumps(parsed_good)
        print("REAL SERVER: allowed read returned expected file", flush=True)

        blocked = await asyncio.wait_for(proxy.handle_message(request(
            3, "tools/call", {
                "name": "write_file",
                "arguments": {"path": str(testfile), "content": "ATTACK"},
            },
        )), timeout=30)
        parsed_blocked = json.loads(blocked)
        assert parsed_blocked["error"]["code"] == proxy.SECURITY_BLOCK_CODE
        assert "DENY_DANGEROUS_TOOL" in parsed_blocked["error"]["message"]
        assert testfile.read_text(encoding="utf-8") == "known-good-content"
        print("REAL SERVER: blocked write did not modify file", flush=True)
    finally:
        await asyncio.wait_for(proxy.stop(), timeout=30)


@pytest.mark.skipif(
    shutil.which("npx") is None or os.environ.get("MCP_RUN_REAL_SERVER") != "1",
    reason="Requires explicit MCP_RUN_REAL_SERVER=1 and Node/npm",
)
def test_official_filesystem_mcp_server():
    with tempfile.TemporaryDirectory(prefix="mcp-gateway-live-") as tmp:
        asyncio.run(live_scenario(Path(tmp)))
