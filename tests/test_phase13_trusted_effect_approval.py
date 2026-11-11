"""No-network tests for trusted exact-operation approval before MCP side effects."""

from __future__ import annotations

import asyncio
import json

import pytest

from mcp_monitor.policy.policy_engine import PolicyEngine
from mcp_monitor.protocol.effect_authority import EffectPermit, TrustedEffectAuthority
from mcp_monitor.protocol.effect_journal import DurableEffectJournal
from mcp_monitor.proxy.stdio_proxy import StdioMCPProxy

PRINCIPAL = "tenantA:alice"
SERVER = "trusted"
TOOL = "update_dependency"
ARGS = {"package": "safe-package", "version": "1.1.0", "expected_previous": "1.0.0"}


class ControlledTransport:
    def __init__(self) -> None:
        self.sent: list[bytes] = []

    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        pass

    async def send(self, data: bytes) -> None:
        self.sent.append(data)

    async def receive(self) -> bytes:
        return b'{"jsonrpc":"2.0","id":7,"result":{"status":"synthetic"}}'


def request(*, key: str = "permit-01", arguments: dict | None = None) -> bytes:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": TOOL,
                "_gateway_operation_key": key,
                "arguments": ARGS if arguments is None else arguments,
            },
        }
    ).encode()


def approval(*, principal: str = PRINCIPAL, key: str = "permit-01") -> TrustedEffectAuthority:
    return TrustedEffectAuthority(
        [
            EffectPermit.for_arguments(
                principal=principal,
                server=SERVER,
                tool=TOOL,
                operation_key=key,
                arguments=ARGS,
            )
        ]
    )


def gateway(tmp_path, *, approved=None, principal: str = PRINCIPAL):
    transport = ControlledTransport()
    journal = DurableEffectJournal.bootstrap(tmp_path / "effect-journal.sqlite3")
    proxy = StdioMCPProxy(
        ["fake"],
        transport=transport,
        server_id=SERVER,
        authenticated_principal=principal,
        strict_mcp_methods=True,
        policy_engine=PolicyEngine(allowed_servers={SERVER}, allowed_tools={TOOL}),
        effect_journal=journal,
        effect_tools={TOOL},
        effect_authority=approved,
    )
    return proxy, transport, journal


def test_operator_approved_exact_effect_forwarded_once(tmp_path) -> None:
    proxy, transport, journal = gateway(tmp_path, approved=approval())
    result = json.loads(asyncio.run(proxy.handle_message(request())))
    assert result["result"]["status"] == "synthetic"
    assert len(transport.sent) == 1
    sent = json.loads(transport.sent[0])
    assert "_gateway_operation_key" not in sent["params"]
    assert sent["params"]["arguments"] == ARGS
    assert (
        journal.status(principal=PRINCIPAL, server=SERVER, tool=TOOL, operation_key="permit-01")
        == "COMPLETED"
    )
    denied = json.loads(asyncio.run(proxy.handle_message(request())))
    assert denied["error"]["code"] == proxy.SECURITY_BLOCK_CODE
    assert len(transport.sent) == 1


@pytest.mark.parametrize(
    "key,arguments,principal",
    [
        ("unknown-permit", ARGS, PRINCIPAL),
        ("permit-01", {**ARGS, "version": "4.0.0"}, PRINCIPAL),
        ("permit-01", {**ARGS, "path": "/private"}, PRINCIPAL),
        ("permit-01", {}, PRINCIPAL),
        ("permit-01", ARGS, "tenantB:alice"),
    ],
)
def test_unapproved_or_spoofed_operation_denied_before_send(
    tmp_path, key: str, arguments: dict, principal: str
) -> None:
    proxy, transport, _ = gateway(tmp_path, approved=approval(), principal=principal)
    result = json.loads(asyncio.run(proxy.handle_message(request(key=key, arguments=arguments))))
    assert result["error"]["code"] == proxy.SECURITY_BLOCK_CODE
    assert transport.sent == []


def test_missing_authority_blocks_hardened_gateway_at_constructor(tmp_path) -> None:
    with pytest.raises(ValueError, match="trusted operator approval"):
        gateway(tmp_path, approved=None)


def test_duplicate_operator_approvals_rejected() -> None:
    permit = EffectPermit.for_arguments(
        principal=PRINCIPAL, server=SERVER, tool=TOOL, operation_key="same", arguments=ARGS
    )
    with pytest.raises(ValueError, match="duplicated"):
        TrustedEffectAuthority([permit, permit])
