"""Regression tests for hardened MCP tool discovery.

All tests use a fake transport. No credentials, network access or paid APIs.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from mcp_monitor.policy.policy_engine import PolicyEngine
from mcp_monitor.proxy.stdio_proxy import StdioMCPProxy


class DiscoveryTransport:
    def __init__(self, result: object):
        self.result = result
        self.sent: list[bytes] = []

    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        pass

    async def send(self, data: bytes) -> None:
        self.sent.append(data)

    async def receive(self) -> bytes:
        return json.dumps({"jsonrpc": "2.0", "id": 1, "result": self.result}).encode()


def _list_request() -> bytes:
    return b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'


def _run(result: object, *, allowed: set[str] | None = None, strict: bool = True):
    downstream = DiscoveryTransport(result)
    proxy = StdioMCPProxy(
        ["fake"],
        transport=downstream,
        strict_mcp_methods=strict,
        server_id="trusted",
        policy_engine=PolicyEngine(allowed_servers={"trusted"}, allowed_tools=allowed),
    )
    answer = json.loads(asyncio.run(proxy.handle_message(_list_request())))
    return answer, downstream


def test_hardened_discovery_omits_forbidden_tool_description() -> None:
    answer, downstream = _run(
        {
            "tools": [
                {"name": "read_manifest", "description": "read approved manifest"},
                {"name": "exfiltrate", "description": "SECRET_MARKER_FORBIDDEN_TOOL"},
                {"name": "shell_exec", "description": "dangerous even if explicitly listed"},
            ]
        },
        allowed={"read_manifest", "shell_exec"},
    )
    assert "error" not in answer
    assert [tool["name"] for tool in answer["result"]["tools"]] == ["read_manifest"]
    assert "SECRET_MARKER_FORBIDDEN_TOOL" not in json.dumps(answer)
    assert downstream.sent == [_list_request() + b"\n"]


def test_empty_allowlist_returns_no_tools() -> None:
    answer, _ = _run({"tools": [{"name": "read_manifest"}]}, allowed=set())
    assert answer["result"]["tools"] == []


@pytest.mark.parametrize(
    "bad_result",
    [
        {},
        {"tools": {}},
        {"tools": [None]},
        {"tools": [{"name": ""}]},
        {"tools": [{"name": "read_manifest"}, {"name": "read_manifest"}]},
    ],
)
def test_invalid_discovery_is_rejected(bad_result: object) -> None:
    answer, _ = _run(bad_result, allowed={"read_manifest"})
    assert answer["error"]["code"] == StdioMCPProxy.SECURITY_BLOCK_CODE
    assert "result" not in answer


def test_hardened_discovery_refuses_missing_capability_allowlist() -> None:
    answer, _ = _run({"tools": [{"name": "read_manifest"}]}, allowed=None)
    assert answer["error"]["code"] == StdioMCPProxy.SECURITY_BLOCK_CODE


def test_legacy_discovery_behavior_not_silently_changed() -> None:
    original = {"tools": [{"name": "read_manifest"}, {"name": "other_tool"}]}
    answer, _ = _run(original, allowed={"read_manifest"}, strict=False)
    assert answer["result"]["tools"] == original["tools"]
