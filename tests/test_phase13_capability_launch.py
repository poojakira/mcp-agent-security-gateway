"""Phase 13 default-deny capability and safe-launch regression checks.

No live service credentials or network calls are used.
"""

from __future__ import annotations

import asyncio
import json
import sys
from unittest.mock import patch

import pytest

from mcp_monitor.policy.policy_engine import PolicyEngine, ReasonCode
from mcp_monitor.proxy.stdio_proxy import StdioMCPProxy, main


class SpyTransport:
    def __init__(self) -> None:
        self.sent: list[bytes] = []

    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        pass

    async def send(self, data: bytes) -> None:
        self.sent.append(data)

    async def receive(self) -> bytes:
        return b'{"jsonrpc":"2.0","id":1,"result":{"ok":true}}'


def _tool(name: str) -> bytes:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": {}},
        }
    ).encode()


def test_unlisted_tool_never_reaches_downstream() -> None:
    transport = SpyTransport()
    proxy = StdioMCPProxy(
        ["placeholder"],
        transport=transport,
        server_id="trusted",
        policy_engine=PolicyEngine(allowed_servers={"trusted"}, allowed_tools={"read_manifest"}),
    )
    response = asyncio.run(proxy.handle_message(_tool("write_file")))
    assert json.loads(response)["error"]["code"] == proxy.SECURITY_BLOCK_CODE
    assert transport.sent == []


def test_listed_tool_passes_capability_gate() -> None:
    transport = SpyTransport()
    proxy = StdioMCPProxy(
        ["placeholder"],
        transport=transport,
        server_id="trusted",
        policy_engine=PolicyEngine(allowed_servers={"trusted"}, allowed_tools={"read_manifest"}),
    )
    response = asyncio.run(proxy.handle_message(_tool("read_manifest")))
    assert json.loads(response)["result"]["ok"] is True
    assert transport.sent == [_tool("read_manifest") + b"\n"]


def test_dangerous_tool_stays_denied_even_if_listed() -> None:
    policy = PolicyEngine(allowed_servers={"trusted"}, allowed_tools={"shell_exec"})
    decision = policy.evaluate({"server_id": "trusted", "name": "shell_exec", "arguments": {}})
    assert decision.allowed is False
    assert decision.reason_code is ReasonCode.DENY_DANGEROUS_TOOL


def test_empty_allowlist_rejects_every_tool() -> None:
    decision = PolicyEngine(allowed_servers={"trusted"}, allowed_tools=set()).evaluate(
        {"server_id": "trusted", "name": "read_file", "arguments": {}}
    )
    assert decision.reason_code is ReasonCode.DENY_TOOL_NOT_ALLOWED


def test_invalid_allowlist_rejected_at_construction() -> None:
    with pytest.raises(ValueError, match="allowed_tools"):
        PolicyEngine(allowed_servers={"trusted"}, allowed_tools={"", "read_file"})


@pytest.mark.parametrize(
    "args,reason",
    [
        (["--", "echo", "hello"], "--allow-tool"),
        (
            ["--allow-tool", "read_file", "--", "echo", "hello"],
            "--offline-sandbox-image",
        ),
        (
            [
                "--allow-tool",
                "read_file",
                "--unsafe-local-dev",
                "--offline-sandbox-image",
                "sha256:example",
                "--",
                "echo",
                "hello",
            ],
            "cannot be combined",
        ),
    ],
)
def test_cli_refuses_insecure_configuration(args: list[str], reason: str) -> None:
    with patch.object(sys, "argv", ["mcp-gateway", *args]):
        with pytest.raises(SystemExit) as exit_info:
            main()
    assert exit_info.value.code == 2


@pytest.mark.parametrize("method", ["resources/read", "prompts/get", "sampling/createMessage"])
def test_hardened_proxy_denies_non_tool_method(method: str) -> None:
    transport = SpyTransport()
    proxy = StdioMCPProxy(
        ["placeholder"],
        transport=transport,
        server_id="trusted",
        strict_mcp_methods=True,
        policy_engine=PolicyEngine(allowed_servers={"trusted"}, allowed_tools={"read_manifest"}),
    )
    message = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": {}}).encode()
    response = asyncio.run(proxy.handle_message(message))
    assert json.loads(response)["error"]["code"] == proxy.SECURITY_BLOCK_CODE
    assert transport.sent == []


def test_production_cli_refuses_unsafe_uncontained_launch(monkeypatch) -> None:
    monkeypatch.setenv("MCP_ENV", "production")
    with patch.object(
        sys,
        "argv",
        [
            "mcp-gateway",
            "--allow-tool",
            "read_manifest",
            "--unsafe-local-dev",
            "--",
            "python",
            "-m",
            "mcp_monitor.protected_repo_server",
        ],
    ):
        with pytest.raises(SystemExit) as exit_info:
            main()
    assert exit_info.value.code == 2


@pytest.mark.parametrize(
    ("options", "expected"),
    [
        (["--unsafe-local-dev"], "pinned offline Docker"),
        (["--internal-sandbox-image", "sha256:" + "a" * 64,
          "--internal-network-id", "b" * 64,
          "--internal-proxy-id", "c" * 64,
          "--internal-proxy-name", "mcp-egress-test"], "pinned offline Docker"),
        (["--offline-sandbox-image", "sha256:" + "a" * 64,
          "--allow-egress-host", "approved.example"], "forbids outbound"),
    ],
)
def test_production_stdio_refuses_uncontained_or_networked_profiles(
    monkeypatch, options: list[str], expected: str, capsys
) -> None:
    monkeypatch.setenv("MCP_ENV", "production")
    with patch.object(
        sys,
        "argv",
        ["mcp-gateway", "--allow-tool", "read_manifest", *options, "--", "python", "-V"],
    ):
        with pytest.raises(SystemExit) as exception:
            main()
    assert exception.value.code == 2
    assert expected in capsys.readouterr().err


def test_hardened_proxy_allows_protocol_handshake() -> None:
    class ValidToolListTransport(SpyTransport):
        async def receive(self) -> bytes:
            return json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {"tools": [{"name": "read_manifest", "description": "safe read"}]},
                }
            ).encode()

    transport = ValidToolListTransport()
    proxy = StdioMCPProxy(
        ["placeholder"],
        transport=transport,
        server_id="trusted",
        strict_mcp_methods=True,
        policy_engine=PolicyEngine(allowed_servers={"trusted"}, allowed_tools={"read_manifest"}),
    )
    message = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}).encode()
    response = asyncio.run(proxy.handle_message(message))
    assert [tool["name"] for tool in json.loads(response)["result"]["tools"]] == ["read_manifest"]
    assert transport.sent == [message + b"\n"]


def test_concurrent_nonmultiplexed_calls_preserve_response_pairing() -> None:
    class SingleFlightTransport(SpyTransport):
        def __init__(self) -> None:
            super().__init__()
            self.pending_id: int | None = None
            self.max_active = 0

        async def send(self, data: bytes) -> None:
            assert self.pending_id is None, "second request sent before first reply"
            self.pending_id = json.loads(data)["id"]
            self.max_active = max(self.max_active, 1)
            self.sent.append(data)

        async def receive(self) -> bytes:
            await asyncio.sleep(0.02)
            assert self.pending_id is not None
            result = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": self.pending_id,
                    "result": {"ok": True},
                }
            ).encode()
            self.pending_id = None
            return result

    async def scenario() -> None:
        transport = SingleFlightTransport()
        proxy = StdioMCPProxy(
            ["placeholder"],
            transport=transport,
            server_id="trusted",
            policy_engine=PolicyEngine(
                allowed_servers={"trusted"}, allowed_tools={"read_manifest"}
            ),
        )
        first = json.loads(_tool("read_manifest"))
        second = json.loads(_tool("read_manifest"))
        second["id"] = 2
        replies = await asyncio.gather(
            proxy.handle_message(json.dumps(first).encode()),
            proxy.handle_message(json.dumps(second).encode()),
        )
        assert [json.loads(reply)["id"] for reply in replies] == [1, 2]
        assert all("result" in json.loads(reply) for reply in replies)
        assert len(transport.sent) == 2

    asyncio.run(scenario())
