"""Phase 8: durable signed local authority with multi-process revocation evidence."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import sqlite3
import subprocess
import sys

import pytest

from mcp_monitor.policy.acl_guard import AccessDenied, ACLGuard
from mcp_monitor.policy.durable_authority import SQLitePermissionAuthority
from mcp_monitor.proxy.stdio_proxy import StdioMCPProxy


KEY = b"SYNTHETIC_PHASE8_HMAC_KEY_NOT_FOR_DEPLOYMENT_0001"
PRINCIPAL = "10:team-alpha:alice"
RESOURCE = "/synthetic/private.txt"
SESSION = ("team-alpha", "session-01", "token-01")


@pytest.fixture
def authority(tmp_path):
    path = tmp_path / "permissions.sqlite3"
    store = SQLitePermissionAuthority.bootstrap(
        path, key=KEY, grants={PRINCIPAL: {RESOURCE}}
    )
    return path, store


def test_initial_signed_decision_and_durable_revision(authority) -> None:
    path, store = authority
    assert store.check(PRINCIPAL, RESOURCE)
    assert store.revision == 0
    next_store = SQLitePermissionAuthority(path, key=KEY)
    assert next_store.check(PRINCIPAL, RESOURCE)


def test_two_nodes_see_revocation_without_resync(authority) -> None:
    path, writer = authority
    first = SQLitePermissionAuthority(path, key=KEY)
    second = SQLitePermissionAuthority(path, key=KEY)
    guards = [
        ACLGuard({PRINCIPAL: {RESOURCE}}, authority_check=node.check)
        for node in (first, second)
    ]
    for guard in guards:
        guard.check(PRINCIPAL, RESOURCE)
    assert writer.set_grant(PRINCIPAL, RESOURCE, False, expected_revision=0) == 1
    for guard in guards:
        with pytest.raises(AccessDenied):
            guard.check(PRINCIPAL, RESOURCE)
    assert SQLitePermissionAuthority(path, key=KEY, minimum_revision=1).check(
        PRINCIPAL, RESOURCE
    ) is False


def test_stale_writer_conflict_fails_closed(authority) -> None:
    path, writer = authority
    other = SQLitePermissionAuthority(path, key=KEY)
    assert writer.set_grant(PRINCIPAL, RESOURCE, False, expected_revision=0) == 1
    with pytest.raises(AccessDenied, match="Stale"):
        other.set_grant(PRINCIPAL, RESOURCE, True, expected_revision=0)
    assert other.check(PRINCIPAL, RESOURCE) is False


def test_replay_and_reverse_permission_change_requires_new_sequence(authority) -> None:
    _, store = authority
    store.set_grant(PRINCIPAL, RESOURCE, False, expected_revision=0)
    with pytest.raises(AccessDenied):
        store.set_grant(PRINCIPAL, RESOURCE, True, expected_revision=0)
    assert store.set_grant(PRINCIPAL, RESOURCE, True, expected_revision=1) == 2
    assert store.check(PRINCIPAL, RESOURCE) is True


def test_signed_snapshot_tampering_fails_closed(authority) -> None:
    path, store = authority
    with sqlite3.connect(path) as db:
        db.execute("UPDATE authority SET snapshot = ? WHERE id = 1", ('{"grants":{}}',))
    with pytest.raises(AccessDenied, match="authentication"):
        store.check(PRINCIPAL, RESOURCE)


def test_incorrect_hmac_key_fails_closed(authority) -> None:
    path, _ = authority
    wrong = SQLitePermissionAuthority(path, key=b"x" * 32)
    with pytest.raises(AccessDenied, match="authentication"):
        wrong.check(PRINCIPAL, RESOURCE)


def test_deleted_db_never_reinitialized_as_permissive(authority) -> None:
    path, store = authority
    path.unlink()
    with pytest.raises(AccessDenied, match="unavailable"):
        store.check(PRINCIPAL, RESOURCE)
    assert not path.exists()


def test_signed_rollback_detected_by_live_reader_and_trusted_restart_floor(authority, tmp_path) -> None:
    path, store = authority
    old = tmp_path / "old-state.sqlite3"
    shutil.copyfile(path, old)
    store.set_grant(PRINCIPAL, RESOURCE, False, expected_revision=0)
    assert not store.check(PRINCIPAL, RESOURCE)
    shutil.copyfile(old, path)
    with pytest.raises(AccessDenied, match="rollback"):
        store.check(PRINCIPAL, RESOURCE)
    restarted = SQLitePermissionAuthority(path, key=KEY, minimum_revision=1)
    with pytest.raises(AccessDenied, match="rollback"):
        restarted.check(PRINCIPAL, RESOURCE)
    # An unanchored new process cannot detect a fully signed historical state.
    assert SQLitePermissionAuthority(path, key=KEY).check(PRINCIPAL, RESOURCE)


def test_session_revocation_is_durable_for_separate_readers(authority) -> None:
    path, writer = authority
    verifier_a = SQLitePermissionAuthority(path, key=KEY)
    verifier_b = SQLitePermissionAuthority(path, key=KEY)
    assert verifier_a.is_active(*SESSION)
    assert verifier_b.is_active(*SESSION)
    assert writer.revoke_session(*SESSION, expected_revision=0) == 1
    assert not verifier_a.is_active(*SESSION)
    assert not verifier_b.is_active(*SESSION)
    assert not SQLitePermissionAuthority(path, key=KEY).is_active(*SESSION)


def test_repeated_revocation_is_idempotent_but_advances_sequence(authority) -> None:
    _, store = authority
    assert store.revoke_session(*SESSION, expected_revision=0) == 1
    assert store.revoke_session(*SESSION, expected_revision=1) == 2
    assert not store.is_active(*SESSION)


@pytest.mark.parametrize("key", [b"", b"short", "not-bytes", None])
def test_rejects_invalid_shared_hmac_keys(tmp_path, key) -> None:
    with pytest.raises(ValueError):
        SQLitePermissionAuthority(tmp_path / "auth.db", key=key)


def test_reinitialization_cannot_reset_revoked_permissions(authority) -> None:
    path, store = authority
    store.set_grant(PRINCIPAL, RESOURCE, False, expected_revision=0)
    with pytest.raises(AccessDenied, match="already initialized"):
        SQLitePermissionAuthority.bootstrap(path, key=KEY, grants={PRINCIPAL: {RESOURCE}})
    assert not store.check(PRINCIPAL, RESOURCE)


def test_wrong_or_malformed_permission_updates_denied(authority) -> None:
    _, store = authority
    with pytest.raises(AccessDenied):
        store.set_grant(PRINCIPAL, RESOURCE, "yes", expected_revision=0)
    with pytest.raises(AccessDenied):
        store.set_grant(PRINCIPAL, RESOURCE, True, expected_revision=True)
    with pytest.raises(AccessDenied):
        store.set_grant("", RESOURCE, True, expected_revision=0)
    assert store.revision == 0


def test_pre_retrieval_filter_uses_authoritative_state(authority) -> None:
    _, store = authority
    guard = ACLGuard(
        {PRINCIPAL: {RESOURCE}},
        authority_check=store.check,
    )
    visited = []
    def backend(query, ids):
        visited.append(ids)
        return [{"resource_id": res, "content": "synthetic"} for res in ids]
    assert guard.authorized_search(PRINCIPAL, "synthetic", backend)
    store.set_grant(PRINCIPAL, RESOURCE, False, expected_revision=0)
    assert guard.authorized_search(PRINCIPAL, "synthetic", backend) == []
    assert len(visited) == 1


class FakeTransport:
    def __init__(self):
        self.sent = []
        self.waiting = asyncio.Event()
        self.release = asyncio.Event()

    async def send(self, message):
        self.sent.append(message)

    async def receive(self):
        self.waiting.set()
        await self.release.wait()
        return b'{"jsonrpc":"2.0","id":9,"result":{"content":"SYNTHETIC_PRIVATE_MARKER"}}'

    async def start(self):
        pass

    async def stop(self):
        pass


def test_inflight_revocation_does_not_release_protected_result(authority) -> None:
    async def scenario():
        _, writer = authority
        transport = FakeTransport()
        guard = ACLGuard({PRINCIPAL: {RESOURCE}}, authority_check=writer.check)
        proxy = StdioMCPProxy(
            command=["synthetic"],
            transport=transport,
            acl_guard=guard,
            authenticated_principal=PRINCIPAL,
            protected_resource_tools={"read_file": "path"},
        )
        req = json.dumps({
            "jsonrpc": "2.0", "id": 9, "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": RESOURCE}},
        }).encode()
        task = asyncio.create_task(proxy.handle_message(req))
        try:
            await asyncio.wait_for(transport.waiting.wait(), timeout=3.0)
            writer.set_grant(PRINCIPAL, RESOURCE, False, expected_revision=0)
        finally:
            transport.release.set()
        raw = await asyncio.wait_for(task, timeout=3.0)
        result = json.loads(raw)
        assert result["error"]["code"] == StdioMCPProxy.SECURITY_BLOCK_CODE
        assert "SYNTHETIC_PRIVATE_MARKER" not in raw.decode()
        assert len(transport.sent) == 1

    asyncio.run(scenario())


def test_two_real_python_processes_observe_shared_durable_revocation(authority) -> None:
    path, writer = authority
    # Separate, persistent Python worker processes; they keep stale local
    # ACL snapshots but consult the same authenticated SQLite source.
    script = '''
import sys
from mcp_monitor.policy.acl_guard import ACLGuard, AccessDenied
from mcp_monitor.policy.durable_authority import SQLitePermissionAuthority
name, resource = sys.argv[2:4]
auth = SQLitePermissionAuthority(sys.argv[1], key=b"SYNTHETIC_PHASE8_HMAC_KEY_NOT_FOR_DEPLOYMENT_0001")
guard = ACLGuard({name: {resource}}, authority_check=auth.check)
for line in sys.stdin:
    if line.strip() == "quit":
        break
    try:
        guard.check(name, resource)
        print("allow", flush=True)
    except AccessDenied:
        print("deny", flush=True)
'''
    workers = [
        subprocess.Popen(
            [sys.executable, "-u", "-c", script, str(path), PRINCIPAL, RESOURCE],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(2)
    ]
    try:
        for worker in workers:
            assert worker.stdin is not None and worker.stdout is not None
            worker.stdin.write("check\n")
            worker.stdin.flush()
            assert worker.stdout.readline().strip() == "allow"
        writer.set_grant(PRINCIPAL, RESOURCE, False, expected_revision=0)
        for worker in workers:
            worker.stdin.write("check\n")
            worker.stdin.flush()
            assert worker.stdout.readline().strip() == "deny"
    finally:
        for worker in workers:
            if worker.stdin:
                worker.stdin.write("quit\n")
                worker.stdin.close()
            try:
                worker.wait(timeout=5)
            except subprocess.TimeoutExpired:
                worker.kill()
                worker.wait(timeout=5)
            if worker.stdout:
                worker.stdout.close()
            if worker.stderr:
                worker.stderr.close()
            assert worker.returncode == 0
