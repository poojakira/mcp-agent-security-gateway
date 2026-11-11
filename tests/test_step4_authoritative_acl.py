"""Step 4 optional authoritative ACL verification on the real stdio proxy path.

This file simulates two independent in-process gateway ACL snapshots backed by
one operator-controlled permission source. It is NOT a distributed CDC or
authentication integration.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from mcp_monitor.policy.acl_guard import AccessDenied, ACLGuard
from mcp_monitor.proxy.stdio_proxy import StdioMCPProxy

RESOURCE = "/synthetic/private.txt"
USER = "operator-authenticated-user"


class SharedAuthority:
    def __init__(self) -> None:
        self.allowed: set[tuple[str, str]] = {(USER, RESOURCE)}
        self.fail = False

    def check(self, principal: str, resource: str) -> bool:
        if self.fail:
            raise RuntimeError("SYNTHETIC_AUTHORITY_SECRET")
        return (principal, resource) in self.allowed

    def revoke(self) -> None:
        self.allowed.discard((USER, RESOURCE))


class PausedTransport:
    def __init__(self) -> None:
        self.sent: list[bytes] = []
        self.waiting = asyncio.Event()
        self.release = asyncio.Event()
        self.pause = False

    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        pass

    async def send(self, raw: bytes) -> None:
        self.sent.append(raw)

    async def receive(self) -> bytes:
        if self.pause:
            self.waiting.set()
            await self.release.wait()
        return b'{"jsonrpc":"2.0","id":7,"result":{"content":"SYNTHETIC_PRIVATE_MARKER"}}'


def make_call(arguments: dict | None = None) -> bytes:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": arguments or {"path": RESOURCE},
            },
        }
    ).encode()


def make_proxy(guard: ACLGuard, transport: PausedTransport) -> StdioMCPProxy:
    return StdioMCPProxy(
        command=["synthetic-test-server"],
        transport=transport,
        acl_guard=guard,
        authenticated_principal=USER,
        protected_resource_tools={"read_file": "path"},
    )


def test_unconfigured_authority_retains_documented_local_only_behavior() -> None:
    guard = ACLGuard({USER: {RESOURCE}})
    guard.check(USER, RESOURCE)


def test_two_stale_local_snapshots_observe_shared_revocation() -> None:
    authority = SharedAuthority()
    guard_a = ACLGuard({USER: {RESOURCE}}, authority_check=authority.check)
    guard_b = ACLGuard({USER: {RESOURCE}}, authority_check=authority.check)
    guard_a.check(USER, RESOURCE)
    guard_b.check(USER, RESOURCE)
    authority.revoke()
    for guard in (guard_a, guard_b):
        with pytest.raises(AccessDenied):
            guard.check(USER, RESOURCE)


def test_revoked_resource_is_filtered_before_search_backend_runs() -> None:
    authority = SharedAuthority()
    guard = ACLGuard(
        {USER: {RESOURCE, "/synthetic/public.txt"}},
        authority_check=authority.check,
    )
    authority.revoke()
    visited: list[frozenset[str]] = []

    def backend(query: str, allowed: frozenset[str]) -> list[dict]:
        visited.append(allowed)
        return [{"resource_id": key, "content": query} for key in allowed]

    result = guard.authorized_search(USER, "controlled", backend)
    assert result == []
    assert visited == []


def test_partial_revocation_removes_resource_from_retrieval_scope() -> None:
    authority = SharedAuthority()
    guard = ACLGuard({USER: {RESOURCE, "/synthetic/public.txt"}}, authority_check=authority.check)
    visited: list[frozenset[str]] = []

    def backend(query: str, allowed: frozenset[str]) -> list[dict]:
        visited.append(allowed)
        return [{"resource_id": key, "content": query} for key in allowed]

    result = guard.authorized_search(USER, "controlled", backend)
    assert [item["resource_id"] for item in result] == [RESOURCE]
    assert visited == [frozenset({RESOURCE})]


@pytest.mark.parametrize("answer", [None, 1, "allowed", [], False])
def test_non_true_authority_answer_denies_access(answer: object) -> None:
    guard = ACLGuard({USER: {RESOURCE}}, authority_check=lambda p, r: answer)
    with pytest.raises(AccessDenied):
        guard.check(USER, RESOURCE)


def test_unavailable_authority_denies_without_leaking_exception_message() -> None:
    authority = SharedAuthority()
    guard = ACLGuard({USER: {RESOURCE}}, authority_check=authority.check)
    authority.fail = True
    with pytest.raises(AccessDenied, match="verification unavailable") as err:
        guard.check(USER, RESOURCE)
    assert "SYNTHETIC_AUTHORITY_SECRET" not in str(err.value)


def test_search_backend_not_called_when_authority_unavailable() -> None:
    authority = SharedAuthority()
    guard = ACLGuard({USER: {RESOURCE}}, authority_check=authority.check)
    authority.fail = True
    visited: list[str] = []

    def backend(query: str, allowed: frozenset[str]) -> list[dict]:
        visited.append(query)
        return []

    with pytest.raises(AccessDenied):
        guard.authorized_search(USER, "query", backend)
    assert visited == []


def test_non_callable_authority_configuration_rejected() -> None:
    with pytest.raises(ValueError, match="authority_check"):
        ACLGuard({USER: {RESOURCE}}, authority_check="client-argument")


def test_agent_cannot_supply_an_alternate_trusted_identity() -> None:
    authority = SharedAuthority()
    guard = ACLGuard({USER: {RESOURCE}}, authority_check=authority.check)
    assert not authority.check("untrusted-user", RESOURCE)
    with pytest.raises(AccessDenied):
        guard.check("untrusted-user", RESOURCE)


def test_revoked_authority_blocks_proxy_before_forwarding() -> None:
    async def scenario() -> None:
        authority = SharedAuthority()
        guard = ACLGuard({USER: {RESOURCE}}, authority_check=authority.check)
        transport = PausedTransport()
        proxy = make_proxy(guard, transport)
        authority.revoke()
        raw = await proxy.handle_message(make_call({"path": RESOURCE, "principal": "other-user"}))
        response = json.loads(raw)
        assert response["error"]["code"] == StdioMCPProxy.SECURITY_BLOCK_CODE
        assert "DENY_RESOURCE_ACL" in response["error"]["data"]["patterns"]
        assert transport.sent == []
        assert "SYNTHETIC_PRIVATE_MARKER" not in raw.decode()

    asyncio.run(scenario())


def test_revocation_during_downstream_read_suppresses_client_response() -> None:
    async def scenario() -> None:
        authority = SharedAuthority()
        guard = ACLGuard({USER: {RESOURCE}}, authority_check=authority.check)
        transport = PausedTransport()
        transport.pause = True
        proxy = make_proxy(guard, transport)
        call = make_call()
        task = asyncio.create_task(proxy.handle_message(call))
        try:
            await asyncio.wait_for(transport.waiting.wait(), timeout=3.0)
            assert not task.done()
            authority.revoke()
        finally:
            transport.release.set()
        raw = await asyncio.wait_for(task, timeout=3.0)
        response = json.loads(raw)
        assert response["error"]["code"] == StdioMCPProxy.SECURITY_BLOCK_CODE
        assert "DENY_RESOURCE_ACL" in response["error"]["data"]["patterns"]
        assert "SYNTHETIC_PRIVATE_MARKER" not in raw.decode()
        assert transport.sent == [call + b"\n"]

    asyncio.run(scenario())
