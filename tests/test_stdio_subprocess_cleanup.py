"""Ensure the downstream MCP process closes its stdio pipes on shutdown."""

from __future__ import annotations

import asyncio
import sys

from mcp_monitor.proxy.stdio_proxy import SubprocessTransport


def test_subprocess_shutdown_closes_stdio_before_loop_exits() -> None:
    async def scenario() -> None:
        script = """
import json
import sys
import time
print(json.dumps({"jsonrpc": "2.0", "id": 1, "result": {}}), flush=True)
print("synthetic diagnostic", file=sys.stderr, flush=True)
time.sleep(30)
"""
        transport = SubprocessTransport([sys.executable, "-u", "-c", script])
        await transport.start()
        process = transport._process
        assert process is not None

        try:
            message = await asyncio.wait_for(transport.receive(), timeout=5.0)
            assert b'"jsonrpc":"2.0"' in message
        finally:
            await asyncio.wait_for(transport.stop(), timeout=12.0)

        assert process.returncode is not None
        assert process.stdin is not None and process.stdin.is_closing()
        assert transport._process is None

        # A repeated stop after cleanup should not raise.
        await transport.stop()

    asyncio.run(scenario())
