"""Race-condition regressions for ACL revocation during in-flight MCP reads.

This is a deterministic controlled transport, not a production CDC integration.
No secrets, external services, or real user resources are used.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from mcp_monitor.policy.acl_guard import ACLGuard, PermissionChange
from mcp_monitor.proxy.stdio_proxy import StdioMCPProxy


class PausedTransport:
    def __init__(self, response: bytes) -> None:
        self.response = response
        self.sent: list[bytes] = []
        self.waiting = asyncio.Event()
        self.release = asyncio.Event()

    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        pass

    async def send(self, data: bytes) -> None:
        self.sent.append(data)

    async def receive(self) -> bytes:
        self.waiting.set()
        await self.release.wait()
        return self.response


def read_request(resource: str, request_id: int = 41) -> bytes:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": resource}},
        }
    ).encode()


@pytest.mark.parametrize("revocation_kind", ["remove_grant", "stale_cdc"])
def test_inflight_revocation_suppresses_response(revocation_kind: str) -> None:
    async def scenario() -> None:
        resource = "/tmp/disposable-protected.txt"
        guard = ACLGuard({"authenticated-user": {resource}})
        response = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 41,
                "result": {"content": [{"type": "text", "text": "PRIVATE_MARKER"}]},
            }
        ).encode()
        transport = PausedTransport(response)
        proxy = StdioMCPProxy(
            command=["fake-server"],
            transport=transport,
            acl_guard=guard,
            authenticated_principal="authenticated-user",
            protected_resource_tools={"read_file": "path"},
        )

        pending = asyncio.create_task(proxy.handle_message(read_request(resource)))
        await asyncio.wait_for(transport.waiting.wait(), timeout=3)
        assert len(transport.sent) == 1  # Authorized before revocation.

        if revocation_kind == "remove_grant":
            guard.apply_change(PermissionChange(1, "authenticated-user", resource, False))
        else:
            from mcp_monitor.policy.acl_guard import AccessDenied

            with pytest.raises(AccessDenied):
                guard.apply_change(PermissionChange(2, "authenticated-user", resource, False))

        transport.release.set()
        raw = await asyncio.wait_for(pending, timeout=3)
        reply = json.loads(raw)
        assert reply["id"] == 41
        assert reply["error"]["code"] == StdioMCPProxy.SECURITY_BLOCK_CODE
        assert "DENY_RESOURCE_ACL" in reply["error"]["data"]["patterns"]
        assert "PRIVATE_MARKER" not in raw.decode()
        assert "result" not in reply
        assert proxy.stats["blocked"] == 1

    asyncio.run(scenario())


def test_inflight_unchanged_permission_allows_response() -> None:
    async def scenario() -> None:
        resource = "/tmp/disposable-protected.txt"
        guard = ACLGuard({"authenticated-user": {resource}})
        response = b'{"jsonrpc":"2.0","id":41,"result":{"content":"SAFE_MARKER"}}'
        transport = PausedTransport(response)
        proxy = StdioMCPProxy(
            command=["fake-server"],
            transport=transport,
            acl_guard=guard,
            authenticated_principal="authenticated-user",
            protected_resource_tools={"read_file": "path"},
        )
        pending = asyncio.create_task(proxy.handle_message(read_request(resource)))
        await asyncio.wait_for(transport.waiting.wait(), timeout=3)
        transport.release.set()
        raw = await asyncio.wait_for(pending, timeout=3)
        assert json.loads(raw)["result"]["content"] == "SAFE_MARKER"
        assert len(transport.sent) == 1

    asyncio.run(scenario())


def test_inflight_batch_revocation_suppresses_all_results() -> None:
    async def scenario() -> None:
        root = "/tmp/disposable-protected.txt"
        guard = ACLGuard({"authenticated-user": {root}})
        response = json.dumps(
            [
                {"jsonrpc": "2.0", "id": 41, "result": {"content": "PRIVATE_MARKER"}},
                {"jsonrpc": "2.0", "id": 42, "result": {"content": "SECOND_MARKER"}},
            ]
        ).encode()
        transport = PausedTransport(response)
        proxy = StdioMCPProxy(
            command=["fake-server"],
            transport=transport,
            acl_guard=guard,
            authenticated_principal="authenticated-user",
            protected_resource_tools={"read_file": "path"},
        )
        batch = json.dumps(
            [
                json.loads(read_request(root, 41)),
                json.loads(read_request(root, 42)),
            ]
        ).encode()
        pending = asyncio.create_task(proxy.handle_message(batch))
        await asyncio.wait_for(transport.waiting.wait(), timeout=3)
        guard.apply_change(PermissionChange(1, "authenticated-user", root, False))
        transport.release.set()
        raw = await asyncio.wait_for(pending, timeout=3)
        replies = json.loads(raw)
        assert [item["id"] for item in replies] == [41, 42]
        assert all(item["error"]["code"] == StdioMCPProxy.SECURITY_BLOCK_CODE for item in replies)
        assert "PRIVATE_MARKER" not in raw.decode()
        assert "SECOND_MARKER" not in raw.decode()

    asyncio.run(scenario())
