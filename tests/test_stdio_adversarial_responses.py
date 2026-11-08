"""Adversarial downstream MCP response tests for the live stdio proxy path.

These use an injectable transport, not a real external MCP server.
They assert that attacker-controlled downstream data never reaches the client
when response parsing, validation, or detection fails.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from mcp_monitor.proxy.stdio_proxy import StdioMCPProxy


class ControlledTransport:
    def __init__(self, response: bytes) -> None:
        self.response = response
        self.sent: list[bytes] = []

    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        pass

    async def send(self, data: bytes) -> None:
        self.sent.append(data)

    async def receive(self) -> bytes:
        return self.response


def call(request_id: int = 71) -> bytes:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "/tmp/safe.txt"}},
        }
    ).encode()


@pytest.mark.parametrize(
    "downstream",
    [
        b'{"jsonrpc":"2.0","id":71,"result":',
        b'{"jsonrpc":"2.0","id":71,"result":{},"result":{"content":"evil"}}',
        b'{"jsonrpc":"2.0","id":71,"method":"tools/call"}',
        b"[]",
        b'[{"jsonrpc":"2.0","id":71,"result":{}},42]',
    ],
    ids=[
        "truncated-json",
        "duplicate-result-keys",
        "request-instead-of-response",
        "empty-batch",
        "mixed-valid-invalid-batch",
    ],
)
def test_malformed_downstream_fails_closed(downstream: bytes) -> None:
    async def scenario() -> None:
        transport = ControlledTransport(downstream)
        proxy = StdioMCPProxy(command=["test-server"], transport=transport)
        reply = json.loads(await proxy.handle_message(call()))
        assert reply["id"] == 71
        assert reply["error"]["code"] == StdioMCPProxy.SECURITY_BLOCK_CODE
        assert "result" not in reply
        assert len(transport.sent) == 1
        assert proxy.stats["blocked"] == 1

    asyncio.run(scenario())


def test_detector_exception_fails_closed_without_leaking_server_text() -> None:
    class CrashingDetector:
        def detect(self, payload):
            if payload.get("name") == "mcp_tool_response":
                raise RuntimeError("synthetic detector outage")
            return False, []

    async def scenario() -> None:
        downstream = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 71,
                "result": {"content": [{"type": "text", "text": "PRIVATE_MARKER"}]},
            }
        ).encode()
        transport = ControlledTransport(downstream)
        proxy = StdioMCPProxy(
            command=["test-server"],
            transport=transport,
            detector=CrashingDetector(),
        )
        raw_reply = await proxy.handle_message(call())
        reply = json.loads(raw_reply)
        assert reply["error"]["code"] == StdioMCPProxy.SECURITY_BLOCK_CODE
        assert "PRIVATE_MARKER" not in raw_reply.decode()
        assert "result" not in reply
        assert len(transport.sent) == 1
        assert proxy.stats["blocked"] == 1

    asyncio.run(scenario())


def test_malicious_member_in_downstream_batch_is_blocked() -> None:
    class MarkerDetector:
        def detect(self, payload):
            if payload.get("name") == "mcp_tool_response" and "ATTACK_MARKER" in str(
                payload.get("arguments", {})
            ):
                return True, ["malicious_downstream_content"]
            return False, []

    async def scenario() -> None:
        response = json.dumps(
            [
                {"jsonrpc": "2.0", "id": 71, "result": {"content": "safe"}},
                {"jsonrpc": "2.0", "id": 72, "result": {"content": "ATTACK_MARKER"}},
            ]
        ).encode()
        transport = ControlledTransport(response)
        proxy = StdioMCPProxy(
            command=["test-server"],
            transport=transport,
            detector=MarkerDetector(),
        )
        raw_reply = await proxy.handle_message(call())
        reply = json.loads(raw_reply)
        assert reply["error"]["code"] == StdioMCPProxy.SECURITY_BLOCK_CODE
        assert "ATTACK_MARKER" not in raw_reply.decode()
        assert "result" not in reply
        assert len(transport.sent) == 1

    asyncio.run(scenario())


@pytest.mark.parametrize("outcome", ["malicious", "malformed", "detector-crash"])
def test_blocked_downstream_batch_replies_to_each_request(outcome: str) -> None:
    """A denied batch must not leave other JSON-RPC request IDs waiting."""

    class ResponseDetector:
        def detect(self, payload):
            if payload.get("name") != "mcp_tool_response":
                return False, []
            if outcome == "detector-crash":
                raise RuntimeError("synthetic response detector failure")
            if "ATTACK_MARKER" in str(payload.get("arguments", {})):
                return True, ["malicious_downstream_content"]
            return False, []

    async def scenario() -> None:
        batch = json.dumps(
            [
                json.loads(call(71)),
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                json.loads(call(72)),
            ]
        ).encode()
        if outcome == "malformed":
            response = b'{"jsonrpc":"2.0","id":71,"result":'
        else:
            response = json.dumps(
                [
                    {"jsonrpc": "2.0", "id": 71, "result": {"content": "safe"}},
                    {"jsonrpc": "2.0", "id": 72, "result": {"content": "ATTACK_MARKER"}},
                ]
            ).encode()
        transport = ControlledTransport(response)
        proxy = StdioMCPProxy(
            command=["test-server"],
            transport=transport,
            detector=ResponseDetector(),
        )

        raw_reply = await proxy.handle_message(batch)
        replies = json.loads(raw_reply)
        assert isinstance(replies, list)
        assert [reply["id"] for reply in replies] == [71, 72]
        assert all(
            reply["error"]["code"] == StdioMCPProxy.SECURITY_BLOCK_CODE for reply in replies
        )
        assert all("result" not in reply for reply in replies)
        assert "ATTACK_MARKER" not in raw_reply.decode()
        assert transport.sent == [batch + b"\n"]
        assert proxy.stats["blocked"] == 1

    asyncio.run(scenario())
