"""P0 regressions against disposable state; no production guarantees implied."""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
from pathlib import Path

import pytest

from mcp_monitor.policy.acl_guard import ACLGuard
from mcp_monitor.protocol.consequence_verifier import (
    Consequence,
    ManifestConsequenceVerifier,
    capture_manifest,
)
from mcp_monitor.protocol.effect_journal import DurableEffectJournal, EffectJournalError
from mcp_monitor.proxy.stdio_proxy import StdioMCPProxy

IDENTITY = dict(
    principal="tenant:alice", server="server", tool="update_dependency", operation_key="op1"
)
ARGS = dict(package="safe", version="2", expected_previous="1")


def test_acknowledgment_cannot_complete_unexecuted_operation(tmp_path):
    journal = DurableEffectJournal.bootstrap(tmp_path / "effects.db")
    journal.reserve(**IDENTITY, arguments=ARGS)
    with pytest.raises(EffectJournalError, match="Independent"):
        journal.mark_completed(**IDENTITY)
    assert journal.status(**IDENTITY) == "UNCERTAIN"


def test_evidence_survives_restart_and_completed_replay_is_denied(tmp_path):
    path = tmp_path / "effects.db"
    journal = DurableEffectJournal.bootstrap(path)
    manifest = tmp_path / "package.json"
    manifest.write_text('{"dependencies":{"safe":"1"}}')
    observer = ManifestConsequenceVerifier(
        tmp_path,
        capture_manifest(tmp_path),
        package="safe",
        expected_previous="1",
        approved_version="2",
    )
    journal.reserve(**IDENTITY, arguments=ARGS, consequence_verifier=observer)
    manifest.write_text('{"dependencies":{"safe":"2"}}')
    journal.reconcile_verified_effect(**IDENTITY, verifier=observer)
    restarted = DurableEffectJournal(path)
    evidence = restarted.evidence(**IDENTITY)
    assert restarted.status(**IDENTITY) == "COMPLETED"
    assert evidence["before_sha256"] != evidence["observed_sha256"]
    assert evidence["observed_at_ns"] > 0
    assert evidence["workspace"] == str(tmp_path)
    with pytest.raises(EffectJournalError):
        restarted.reserve(**IDENTITY, arguments=ARGS)
    assert json.loads(manifest.read_text()) == {"dependencies": {"safe": "2"}}


def test_evidence_failure_rolls_back_completion(tmp_path):
    journal = DurableEffectJournal.bootstrap(tmp_path / "effects.db")
    manifest = tmp_path / "package.json"
    manifest.write_text('{"dependencies":{"safe":"1"}}')
    observer = ManifestConsequenceVerifier(
        tmp_path,
        capture_manifest(tmp_path),
        package="safe",
        expected_previous="1",
        approved_version="2",
    )
    journal.reserve(**IDENTITY, arguments=ARGS, consequence_verifier=observer)
    manifest.write_text('{"dependencies":{"safe":"2"}}')
    with sqlite3.connect(journal._path) as db:
        db.execute("DROP TABLE observations")
    with pytest.raises(EffectJournalError):
        journal.reconcile_verified_effect(**IDENTITY, verifier=observer)
    assert journal.status(**IDENTITY) == "UNCERTAIN"


def test_snapshot_mutation_cannot_authorize_unrelated_modification(tmp_path):
    manifest = tmp_path / "package.json"
    manifest.write_text('{"dependencies":{"safe":"1","other":"1"}}')
    snapshot = capture_manifest(tmp_path)
    observer = ManifestConsequenceVerifier(
        tmp_path, snapshot, package="safe", expected_previous="1", approved_version="2"
    )
    snapshot.content["dependencies"]["other"] = "malicious"
    manifest.write_text('{"dependencies":{"safe":"2","other":"malicious"}}')
    assert observer.inspect().state is Consequence.UNEXPECTED_EFFECT


@pytest.mark.parametrize("attack", ["permissions", "symlink", "hardlink", "corrupt"])
def test_untrusted_journal_storage_denies_reservation(tmp_path, attack):
    path = tmp_path / "effects.db"
    journal = DurableEffectJournal.bootstrap(path)
    if attack == "permissions":
        path.chmod(0o644)
    elif attack == "symlink":
        moved = tmp_path / "moved.db"
        path.rename(moved)
        path.symlink_to(moved)
    elif attack == "hardlink":
        os.link(path, tmp_path / "alias.db")
    else:
        path.write_bytes(b"corrupt")
    with pytest.raises(EffectJournalError):
        journal.reserve(**IDENTITY, arguments=ARGS)


def test_bootstrap_never_adopts_existing_empty_file(tmp_path):
    path = tmp_path / "effects.db"
    path.touch()
    with pytest.raises(EffectJournalError):
        DurableEffectJournal.bootstrap(path)
    assert path.read_bytes() == b""


@pytest.mark.parametrize("multiplexed", [False, True])
def test_revocation_while_waiting_to_dispatch_has_zero_effects(multiplexed):
    async def scenario():
        class Target:
            effects = 0

            async def start(self):
                pass

            async def stop(self):
                pass

            async def send(self, raw):
                self.effects += 1

            async def receive(self):
                await asyncio.Future()

        active = True
        target = Target()
        guard = ACLGuard({"alice": {"resource"}}, authority_check=lambda p, r: active)
        gateway = StdioMCPProxy(
            ["synthetic"],
            transport=target,
            acl_guard=guard,
            authenticated_principal="alice",
            protected_resource_tools={"write_file": "path"},
            multiplexed=multiplexed,
        )
        lock = gateway._transport._send_lock if multiplexed else gateway._exchange_lock
        if multiplexed:
            await gateway.start()
        await lock.acquire()
        call = json.dumps(
            dict(
                jsonrpc="2.0",
                id=1,
                method="tools/call",
                params=dict(name="write_file", arguments=dict(path="resource", content="safe")),
            )
        ).encode()
        task = asyncio.create_task(gateway.handle_message(call))
        await asyncio.sleep(0)
        active = False
        lock.release()
        result = await asyncio.wait_for(task, 1)
        assert "error" in json.loads(result)
        assert target.effects == 0
        if multiplexed:
            await gateway.stop()

    asyncio.run(scenario())


def test_session_and_token_revocation_apply_to_independent_local_readers(tmp_path):
    from mcp_monitor.policy.durable_authority import SQLitePermissionAuthority

    key = os.urandom(32)
    path = tmp_path / "authority.db"
    writer = SQLitePermissionAuthority.bootstrap(path, key=key, grants={"alice": {"resource"}})
    reader = SQLitePermissionAuthority(path, key=key)
    assert reader.is_active("tenant-a", "session", "token-1")
    writer.revoke_entire_session("tenant-a", "session", expected_revision=0)
    assert not reader.is_active("tenant-a", "session", "token-1")
    assert not reader.is_active("tenant-a", "session", "token-2")
    assert reader.is_active("tenant-b", "session", "token-1")
    writer.revoke_token("tenant-a", "token-3", expected_revision=1)
    assert not reader.is_active("tenant-a", "new-session", "token-3")
    assert reader.is_active("tenant-b", "new-session", "token-3")


@pytest.mark.parametrize("attack", ["permissions", "symlink", "hardlink"])
def test_live_revocation_fence_rejects_storage_substitution(tmp_path, attack):
    from mcp_monitor.protocol.revocation_fence import RevocationFence, RevocationFenceError

    path = tmp_path / "fence.db"
    fence = RevocationFence.bootstrap(path, principal="alice")
    if attack == "permissions":
        path.chmod(0o644)
    elif attack == "symlink":
        moved = tmp_path / "moved.db"
        path.rename(moved)
        path.symlink_to(moved)
    else:
        os.link(path, tmp_path / "alias.db")
    effects = []
    with pytest.raises(RevocationFenceError):
        with fence.authorize_effect("alice"):
            effects.append("unauthorized")
    assert effects == []


@pytest.mark.parametrize("component", ["policy", "detector"])
def test_dependency_exception_secrets_are_not_logged_or_returned(component, caplog, monkeypatch):
    class Target:
        effects = 0

        async def send(self, raw):
            self.effects += 1

    marker = "SYNTHETIC-DO-NOT-LOG-EXCEPTION-CONTENT"

    def fail(*args, **kwargs):
        raise RuntimeError(marker)

    target = Target()
    gateway = StdioMCPProxy(["synthetic"], transport=target)
    if component == "policy":
        monkeypatch.setattr(gateway._policy_engine, "evaluate", fail)
    else:
        monkeypatch.setattr(gateway._detector, "detect", fail)
    request = json.dumps(
        dict(
            jsonrpc="2.0",
            id=1,
            method="tools/call",
            params=dict(name="read_file", arguments=dict(path="safe")),
        )
    ).encode()
    response = asyncio.run(gateway.handle_message(request))
    assert "error" in json.loads(response)
    assert target.effects == 0
    assert marker not in response.decode()
    assert marker not in caplog.text


def test_development_servers_do_not_share_predictable_audit_storage(monkeypatch):
    from mcp_monitor.production.config import Config
    from mcp_monitor.production.server import ProductionServer

    for name in ("MCP_ENV", "MCP_WAL_PATH", "MCP_AUDIT_PATH"):
        monkeypatch.delenv(name, raising=False)
    first, second = ProductionServer(Config()), ProductionServer(Config())
    assert first._ephemeral_state.name != second._ephemeral_state.name
    assert Path(first._ephemeral_state.name).stat().st_mode & 0o077 == 0
    assert Path(second._ephemeral_state.name).stat().st_mode & 0o077 == 0


def test_other_workspace_cannot_reconcile_identical_operation(tmp_path):
    journal = DurableEffectJournal.bootstrap(tmp_path / "effects.db")
    observers = []
    for label in ("approved", "other"):
        root = tmp_path / label
        root.mkdir()
        (root / "package.json").write_text('{"dependencies":{"safe":"1"}}')
        observers.append(
            ManifestConsequenceVerifier(
                root,
                capture_manifest(root),
                package="safe",
                expected_previous="1",
                approved_version="2",
            )
        )
    journal.reserve(**IDENTITY, arguments=ARGS, consequence_verifier=observers[0])
    (tmp_path / "other/package.json").write_text('{"dependencies":{"safe":"2"}}')
    with pytest.raises(EffectJournalError, match="resource/preflight"):
        journal.reconcile_verified_effect(**IDENTITY, verifier=observers[1])
    assert journal.status(**IDENTITY) == "UNCERTAIN"
    assert json.loads((tmp_path / "approved/package.json").read_text()) == {
        "dependencies": {"safe": "1"}
    }


def test_unbound_legacy_intent_cannot_gain_reconciliation_authority(tmp_path):
    journal = DurableEffectJournal.bootstrap(tmp_path / "effects.db")
    manifest = tmp_path / "package.json"
    manifest.write_text('{"dependencies":{"safe":"1"}}')
    observer = ManifestConsequenceVerifier(
        tmp_path,
        capture_manifest(tmp_path),
        package="safe",
        expected_previous="1",
        approved_version="2",
    )
    journal.reserve(**IDENTITY, arguments=ARGS)
    manifest.write_text('{"dependencies":{"safe":"2"}}')
    with pytest.raises(EffectJournalError, match="resource/preflight"):
        journal.reconcile_verified_effect(**IDENTITY, verifier=observer)
    assert journal.status(**IDENTITY) == "UNCERTAIN"


def test_stale_preflight_cannot_be_reserved(tmp_path):
    journal = DurableEffectJournal.bootstrap(tmp_path / "effects.db")
    manifest = tmp_path / "package.json"
    manifest.write_text('{"dependencies":{"safe":"1"}}')
    observer = ManifestConsequenceVerifier(
        tmp_path,
        capture_manifest(tmp_path),
        package="safe",
        expected_previous="1",
        approved_version="2",
    )
    manifest.write_text('{"dependencies":{"safe":"99"}}')
    with pytest.raises(EffectJournalError, match="Preflight"):
        journal.reserve(**IDENTITY, arguments=ARGS, consequence_verifier=observer)
    assert journal.status(**IDENTITY) is None
