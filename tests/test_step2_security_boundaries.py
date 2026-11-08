"""Step 2: controlled authorization, recovery and transport failure regressions.

No remote targets or credentials. The two-guard case explicitly documents
that in-memory ACL guards alone do not solve distributed consistency.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from mcp_monitor.policy.acl_guard import ACLGuard, AccessDenied, PermissionChange
from mcp_monitor.policy.policy_engine import PolicyEngine, ReasonCode
from mcp_monitor.proxy.stdio_proxy import StdioMCPProxy


class FailureTransport:
    def __init__(self, fail_at: str) -> None:
        self.fail_at = fail_at
        self.sent: list[bytes] = []

    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        pass

    async def send(self, data: bytes) -> None:
        self.sent.append(data)
        if self.fail_at == "send":
            raise RuntimeError("SYNTHETIC_PRIVATE_TRANSPORT_MESSAGE")

    async def receive(self) -> bytes:
        if self.fail_at == "receive":
            raise RuntimeError("SYNTHETIC_PRIVATE_TRANSPORT_MESSAGE")
        return b'{"jsonrpc":"2.0","id":7,"result":{"content":"safe"}}'


def request(arguments: dict, request_id: int = 7) -> bytes:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": arguments},
        }
    ).encode()


@pytest.mark.parametrize("fail_at", ["send", "receive"])
def test_downstream_failure_returns_structured_denial(fail_at: str) -> None:
    async def scenario() -> None:
        transport = FailureTransport(fail_at)
        proxy = StdioMCPProxy(command=["synthetic"], transport=transport)
        raw = await proxy.handle_message(request({"path": "/disposable/ok"}))
        reply = json.loads(raw)
        assert reply["id"] == 7
        assert reply["error"]["code"] == StdioMCPProxy.SECURITY_BLOCK_CODE
        assert "SYNTHETIC_PRIVATE_TRANSPORT_MESSAGE" not in raw.decode()
        assert "result" not in reply
        assert proxy.stats["blocked"] == 1

    asyncio.run(scenario())


def test_batch_transport_failure_returns_all_request_ids() -> None:
    async def scenario() -> None:
        transport = FailureTransport("receive")
        proxy = StdioMCPProxy(command=["synthetic"], transport=transport)
        raw = await proxy.handle_message(
            json.dumps([json.loads(request({"path": "/tmp/one"}, 7)),
                        json.loads(request({"path": "/tmp/two"}, 8))]).encode()
        )
        errors = json.loads(raw)
        assert [item["id"] for item in errors] == [7, 8]
        assert all("error" in item and "result" not in item for item in errors)

    asyncio.run(scenario())


def test_agent_supplied_principal_cannot_override_trusted_identity() -> None:
    async def scenario() -> None:
        guard = ACLGuard({"alice": {"/private/alice"}, "bob": {"/private/bob"}})
        transport = FailureTransport("none")
        proxy = StdioMCPProxy(
            command=["synthetic"],
            transport=transport,
            acl_guard=guard,
            authenticated_principal="bob",
            protected_resource_tools={"read_file": "path"},
        )
        reply = json.loads(
            await proxy.handle_message(
                request({"path": "/private/alice", "principal": "alice", "user_id": "alice"})
            )
        )
        assert reply["error"]["code"] == StdioMCPProxy.SECURITY_BLOCK_CODE
        assert "DENY_RESOURCE_ACL" in reply["error"]["data"]["patterns"]
        assert transport.sent == []

    asyncio.run(scenario())


def test_missing_trusted_identity_never_forwards_protected_read() -> None:
    async def scenario() -> None:
        transport = FailureTransport("none")
        proxy = StdioMCPProxy(
            command=["synthetic"],
            transport=transport,
            acl_guard=ACLGuard({"alice": {"/private/alice"}}),
            protected_resource_tools={"read_file": "path"},
        )
        reply = json.loads(await proxy.handle_message(request({"path": "/private/alice"})))
        assert reply["error"]["code"] == StdioMCPProxy.SECURITY_BLOCK_CODE
        assert transport.sent == []

    asyncio.run(scenario())


def test_untrusted_restart_denies_until_newer_snapshot() -> None:
    resource = "/private/report"
    first = ACLGuard({"alice": {resource}})
    first.check("alice", resource)
    first.apply_change(PermissionChange(1, "alice", resource, False))
    restarted = ACLGuard({"alice": {resource}}, sequence=1, require_resync=True)
    with pytest.raises(AccessDenied):
        restarted.check("alice", resource)
    with pytest.raises(AccessDenied):
        restarted.replace_snapshot({"alice": {resource}}, sequence=1)
    restarted.replace_snapshot({"alice": set()}, sequence=2)
    with pytest.raises(AccessDenied):
        restarted.check("alice", resource)
    restarted.apply_change(PermissionChange(3, "alice", resource, True))
    restarted.check("alice", resource)


@pytest.mark.parametrize(
    "change",
    [
        PermissionChange(True, "alice", "/private/a", True),
        PermissionChange(1, "alice", "/private/a", "false"),
        PermissionChange(1, 42, "/private/a", False),
        PermissionChange(1, "alice", 4, False),
    ],
)
def test_malformed_permission_event_poison_state(change: PermissionChange) -> None:
    guard = ACLGuard({"alice": {"/private/a"}})
    with pytest.raises(AccessDenied):
        guard.apply_change(change)
    with pytest.raises(AccessDenied):
        guard.check("alice", "/private/a")


def test_stale_second_process_remains_risk_without_distributed_feed() -> None:
    """Regression records the open gap, not a claim of multi-process safety."""
    a = ACLGuard({"alice": {"/private/a"}})
    b = ACLGuard({"alice": {"/private/a"}})
    a.apply_change(PermissionChange(1, "alice", "/private/a", False))
    with pytest.raises(AccessDenied):
        a.check("alice", "/private/a")
    b.check("alice", "/private/a")  # Other node still has a stale snapshot.


@pytest.mark.parametrize(
    "arguments",
    [
        {"url": "https://api.example.com", "host": "unapproved.example"},
        {"url": "https://api.example.com", "endpoint": "http://127.0.0.1/admin"},
        {"url": "https://api.example.com", "target": "https://unapproved.example"},
    ],
)
def test_secondary_egress_destination_cannot_bypass_allowlist(arguments: dict) -> None:
    engine = PolicyEngine(
        allowed_servers={"local"},
        allowed_egress_hosts={"api.example.com"},
    )
    decision = engine.evaluate({"name": "http_get", "server_id": "local", "arguments": arguments})
    assert not decision.allowed
    assert decision.reason_code == ReasonCode.DENY_EGRESS_NOT_ALLOWED


def test_malformed_explicit_egress_destination_denied() -> None:
    engine = PolicyEngine(allowed_servers={"local"}, allowed_egress_hosts={"api.example.com"})
    decision = engine.evaluate(
        {"name": "http_get", "server_id": "local", "egress_destination": 123,
         "arguments": {"url": "https://api.example.com"}}
    )
    assert not decision.allowed
    assert decision.reason_code == ReasonCode.DENY_EGRESS_MALFORMED


def test_all_allowlisted_destinations_can_pass_policy() -> None:
    engine = PolicyEngine(allowed_servers={"local"}, allowed_egress_hosts={"api.example.com"})
    decision = engine.evaluate(
        {"name": "http_get", "server_id": "local",
         "arguments": {"url": "https://api.example.com/a", "host": "api.example.com"}}
    )
    assert decision.allowed
