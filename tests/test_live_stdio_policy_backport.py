"""Live MCP stdio enforcement regressions (no providers, credentials or network)."""

from __future__ import annotations

import asyncio
import json
import sys
from unittest.mock import patch

import pytest

from mcp_monitor.policy.policy_engine import PolicyEngine
from mcp_monitor.proxy.stdio_proxy import StdioMCPProxy, main


class FakeTransport:
    def __init__(self) -> None:
        self.sent: list[bytes] = []

    async def send(self, data: bytes) -> None:
        self.sent.append(data)

    async def receive(self) -> bytes:
        return b'{"jsonrpc":"2.0","id":1,"result":{"ok":true}}'

    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        pass


def call(name: str, arguments: dict | None = None) -> bytes:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        }
    ).encode()


def invoke(message: bytes, *, allowed: set[str] | None = None):
    transport = FakeTransport()
    engine = PolicyEngine(allowed_servers={"local"}, allowed_tools=allowed)
    proxy = StdioMCPProxy(["fake"], transport=transport, policy_engine=engine)
    answer = json.loads(asyncio.run(proxy.handle_message(message)))
    return answer, transport.sent


def test_live_stdio_denies_disallowed_tool_before_send() -> None:
    answer, sent = invoke(call("read_manifest"), allowed={"update_dependency"})
    assert answer["error"]["code"] == StdioMCPProxy.SECURITY_BLOCK_CODE
    assert "DENY_TOOL_NOT_ALLOWED" in answer["error"]["message"]
    assert sent == []


def test_live_stdio_denies_clean_dangerous_tool_before_send() -> None:
    answer, sent = invoke(call("delete_file", {"path": "note.txt"}))
    assert answer["error"]["code"] == StdioMCPProxy.SECURITY_BLOCK_CODE
    assert "DENY_DANGEROUS_TOOL" in answer["error"]["message"]
    assert sent == []


def test_live_stdio_denies_unapproved_destination() -> None:
    answer, sent = invoke(call("http_get", {"url": "https://untrusted.example"}))
    assert "DENY_EGRESS_NOT_ALLOWED" in answer["error"]["message"]
    assert sent == []


def test_live_stdio_allows_exact_approved_tool() -> None:
    message = call("read_manifest")
    answer, sent = invoke(message, allowed={"read_manifest"})
    assert answer["result"]["ok"] is True
    assert sent == [message + b"\n"]


def test_policy_engine_exception_fails_closed() -> None:
    class FailingPolicy:
        def evaluate(self, _):
            raise RuntimeError("unavailable")

    transport = FakeTransport()
    proxy = StdioMCPProxy(["fake"], transport=transport, policy_engine=FailingPolicy())
    result = json.loads(asyncio.run(proxy.handle_message(call("read_manifest"))))
    assert result["error"]["code"] == StdioMCPProxy.SECURITY_BLOCK_CODE
    assert transport.sent == []


def test_mixed_batch_denies_every_member_without_forwarding() -> None:
    message = json.dumps(
        [
            json.loads(call("read_manifest")),
            {**json.loads(call("delete_file")), "id": 2},
        ]
    ).encode()
    answer, sent = invoke(message, allowed={"read_manifest"})
    assert all(item["error"]["code"] == StdioMCPProxy.SECURITY_BLOCK_CODE for item in answer)
    assert sent == []


@pytest.mark.parametrize(
    "argv",
    [
        ["mcp-gateway", "--", "python", "-V"],
        ["mcp-gateway", "--allow-tool", "read_manifest", "--"],
        ["mcp-gateway", "--allow-tool", "read_manifest", "python", "-V"],
    ],
)
def test_cli_denies_unconfigured_or_missing_downstream(argv: list[str]) -> None:
    with patch.object(sys, "argv", argv):
        with pytest.raises(SystemExit) as exc:
            main()
    assert exc.value.code == 2


def test_cli_refuses_uncontained_production_launch(monkeypatch) -> None:
    monkeypatch.setenv("MCP_ENV", "production")
    with patch.object(
        sys,
        "argv",
        ["mcp-gateway", "--allow-tool", "read_manifest", "--", "python", "-V"],
    ):
        with pytest.raises(SystemExit) as exc:
            main()
    assert exc.value.code == 2


@pytest.mark.parametrize("method", ["resources/read", "prompts/get", "custom/run"])
def test_strict_methods_block_alternate_access_paths(method: str) -> None:
    transport = FakeTransport()
    proxy = StdioMCPProxy(
        ["fake"],
        transport=transport,
        strict_mcp_methods=True,
        policy_engine=PolicyEngine(allowed_servers={"local"}, allowed_tools={"read_manifest"}),
    )
    message = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": {"uri": "private"}}
    ).encode()
    response = json.loads(asyncio.run(proxy.handle_message(message)))
    assert response["error"]["code"] == StdioMCPProxy.SECURITY_BLOCK_CODE
    assert transport.sent == []


def test_strict_methods_require_operator_tool_allowlist() -> None:
    with pytest.raises(ValueError, match="trusted tool allowlist"):
        StdioMCPProxy(["fake"], transport=FakeTransport(), strict_mcp_methods=True)


def test_policy_does_not_trust_agent_server_identity() -> None:
    payload = json.loads(call("read_manifest"))
    payload["params"]["server_id"] = "authorized"
    transport = FakeTransport()
    proxy = StdioMCPProxy(
        ["fake"],
        server_id="unapproved",
        transport=transport,
        policy_engine=PolicyEngine(allowed_servers={"authorized"}, allowed_tools={"read_manifest"}),
    )
    answer = json.loads(asyncio.run(proxy.handle_message(json.dumps(payload).encode())))
    assert "DENY_SERVER_NOT_ALLOWED" in answer["error"]["message"]
    assert transport.sent == []
