"""Step 4 protocol-envelope, response-inspection and transport resilience tests.

Only controlled JSON-RPC and an ephemeral local Python child are used.
"""

from __future__ import annotations

import asyncio
import json
import sys

import pytest

from mcp_monitor.proxy.stdio_proxy import StdioMCPProxy, SubprocessTransport


class FixtureTransport:
    def __init__(self, response: bytes, *, delay: float = 0) -> None:
        self.response = response
        self.delay = delay
        self.sent: list[bytes] = []

    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        pass

    async def send(self, data: bytes) -> None:
        self.sent.append(data)

    async def receive(self) -> bytes:
        if self.delay:
            await asyncio.sleep(self.delay)
        return self.response


def request(method: str, request_id: int = 71) -> bytes:
    return json.dumps(
        {"jsonrpc": "2.0", "id": request_id, "method": method, "params": {}}
    ).encode()


@pytest.mark.parametrize(
    "payload",
    [
        {"jsonrpc": "1.0", "id": 71, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": True, "method": "resources/read"},
        {"jsonrpc": "2.0", "id": 71, "method": 42},
        {"jsonrpc": "2.0", "id": 71, "method": "resources/read", "params": "bad"},
        {"jsonrpc": "2.0", "id": 71, "method": "initialize", "result": {}},
        {"jsonrpc": "2.0", "id": 71},
        [
            {"jsonrpc": "2.0", "id": 71, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 71, "method": "resources/read"},
        ],
    ],
)
def test_invalid_rpc_envelopes_are_not_forwarded(payload: object) -> None:
    async def scenario() -> None:
        transport = FixtureTransport(b'{"jsonrpc":"2.0","id":71,"result":{}}')
        proxy = StdioMCPProxy(command=["synthetic"], transport=transport)
        response = json.loads(await proxy.handle_message(json.dumps(payload).encode()))
        assert response["error"]["code"] == -32600
        assert transport.sent == []

    asyncio.run(scenario())


class MarkerDetector:
    def detect(self, payload: dict) -> tuple[bool, list[str]]:
        if payload.get("name") == "mcp_tool_response" and "PRIVATE_INJECTION" in str(
            payload.get("arguments", {})
        ):
            return True, ["synthetic_response_injection"]
        return False, []


@pytest.mark.parametrize("method", ["tools/list", "resources/read", "prompts/get", "initialize"])
def test_untrusted_non_tool_response_is_inspected(method: str) -> None:
    async def scenario() -> None:
        response = json.dumps(
            {"jsonrpc": "2.0", "id": 71, "result": {"content": "PRIVATE_INJECTION"}}
        ).encode()
        transport = FixtureTransport(response)
        proxy = StdioMCPProxy(command=["synthetic"], transport=transport, detector=MarkerDetector())
        raw = await proxy.handle_message(request(method))
        denial = json.loads(raw)
        assert denial["error"]["code"] == StdioMCPProxy.SECURITY_BLOCK_CODE
        assert "PRIVATE_INJECTION" not in raw.decode()
        assert transport.sent == [request(method) + b"\n"]

    asyncio.run(scenario())


def test_benign_non_tool_response_is_preserved() -> None:
    async def scenario() -> None:
        response = b'{"jsonrpc":"2.0","id":71,"result":{"content":"SAFE_MARKER"}}'
        transport = FixtureTransport(response)
        proxy = StdioMCPProxy(command=["synthetic"], transport=transport, detector=MarkerDetector())
        assert await proxy.handle_message(request("resources/read")) == response

    asyncio.run(scenario())


def test_mismatched_non_tool_response_id_is_blocked() -> None:
    async def scenario() -> None:
        transport = FixtureTransport(
            b'{"jsonrpc":"2.0","id":999,"result":{"content":"PRIVATE_MARKER"}}'
        )
        proxy = StdioMCPProxy(command=["synthetic"], transport=transport)
        raw = await proxy.handle_message(request("prompts/get"))
        assert json.loads(raw)["error"]["code"] == StdioMCPProxy.SECURITY_BLOCK_CODE
        assert "PRIVATE_MARKER" not in raw.decode()

    asyncio.run(scenario())


def test_slow_downstream_response_fails_closed() -> None:
    async def scenario() -> None:
        transport = FixtureTransport(
            b'{"jsonrpc":"2.0","id":71,"result":{"content":"PRIVATE_MARKER"}}',
            delay=0.1,
        )
        proxy = StdioMCPProxy(
            command=["synthetic"], transport=transport, response_timeout_seconds=0.001
        )
        raw = await proxy.handle_message(request("resources/read"))
        assert json.loads(raw)["error"]["code"] == StdioMCPProxy.SECURITY_BLOCK_CODE
        assert "PRIVATE_MARKER" not in raw.decode()

    asyncio.run(scenario())


def test_oversized_downstream_result_is_blocked() -> None:
    async def scenario() -> None:
        response = json.dumps(
            {"jsonrpc": "2.0", "id": 71, "result": {"content": "X" * 500}}
        ).encode()
        proxy = StdioMCPProxy(
            command=["synthetic"],
            transport=FixtureTransport(response),
            max_message_bytes=256,
        )
        raw = await proxy.handle_message(request("resources/read"))
        assert json.loads(raw)["error"]["code"] == StdioMCPProxy.SECURITY_BLOCK_CODE

    asyncio.run(scenario())


def test_oversized_request_never_reaches_downstream() -> None:
    async def scenario() -> None:
        transport = FixtureTransport(b'{"jsonrpc":"2.0","id":71,"result":{}}')
        proxy = StdioMCPProxy(
            command=["synthetic"], transport=transport, max_message_bytes=256
        )
        raw = await proxy.handle_message(
            json.dumps(
                {"jsonrpc": "2.0", "id": 71, "method": "resources/read", "params": {"x": "Z" * 500}}
            ).encode()
        )
        assert json.loads(raw)["error"]["code"] == StdioMCPProxy.SECURITY_BLOCK_CODE
        assert transport.sent == []

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "settings",
    [
        {"response_timeout_seconds": 0},
        {"response_timeout_seconds": float("inf")},
        {"response_timeout_seconds": float("nan")},
        {"response_timeout_seconds": True},
        {"max_message_bytes": False},
        {"max_message_bytes": 0},
    ],
)
def test_invalid_transport_limits_are_rejected(settings: dict) -> None:
    with pytest.raises(ValueError):
        StdioMCPProxy(command=["synthetic"], **settings)


def test_local_subprocess_response_line_size_is_bounded() -> None:
    async def scenario() -> None:
        script = "import sys; sys.stdout.write('X' * 500 + '\\n'); sys.stdout.flush()"
        transport = SubprocessTransport(
            [sys.executable, "-u", "-c", script], max_response_bytes=64
        )
        await transport.start()
        try:
            with pytest.raises(ValueError, match="size limit"):
                await asyncio.wait_for(transport.receive(), timeout=5.0)
        finally:
            await asyncio.wait_for(transport.stop(), timeout=5.0)

    asyncio.run(scenario())
