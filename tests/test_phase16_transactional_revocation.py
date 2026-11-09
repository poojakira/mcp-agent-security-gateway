"""Phase 16 bounded revocation races for real local SQLite transactions."""

from __future__ import annotations

import sqlite3

import pytest

from mcp_monitor.protocol.transactional_revocation import (
    RevokedOperation,
    TransactionalRevocationFence,
)


@pytest.fixture
def fence(tmp_path):
    return TransactionalRevocationFence.bootstrap(
        tmp_path / "fence.sqlite", principal="trusted-operator", resource="disposable-ledger"
    )


def test_revoked_before_dispatch_has_zero_effect(fence) -> None:
    rev = fence.current_revision("trusted-operator", "disposable-ledger")
    assert fence.revoke("trusted-operator", "disposable-ledger", expected_revision=rev) == 1
    with pytest.raises(RevokedOperation):
        fence.step(
            "trusted-operator", "disposable-ledger", expected_revision=rev, delta=3
        )
    assert fence.total("disposable-ledger") == 0
    assert fence.effect_count() == 0


def test_queued_operation_with_stale_revision_is_denied(fence) -> None:
    previously_queued_revision = fence.current_revision(
        "trusted-operator", "disposable-ledger"
    )
    fence.revoke(
        "trusted-operator", "disposable-ledger", expected_revision=previously_queued_revision
    )
    with pytest.raises(RevokedOperation):
        fence.step(
            "trusted-operator",
            "disposable-ledger",
            expected_revision=previously_queued_revision,
            delta=5,
        )
    assert fence.effect_count() == 0


def test_multistep_operation_stops_after_revocation_boundary(fence) -> None:
    revision = fence.current_revision("trusted-operator", "disposable-ledger")
    fence.step(
        "trusted-operator", "disposable-ledger", expected_revision=revision, delta=4
    )
    assert fence.total("disposable-ledger") == 4
    fence.revoke("trusted-operator", "disposable-ledger", expected_revision=revision)
    with pytest.raises(RevokedOperation):
        fence.step(
            "trusted-operator", "disposable-ledger", expected_revision=revision, delta=7
        )
    assert fence.total("disposable-ledger") == 4
    assert fence.effect_count() == 1


def test_post_commit_revocation_never_claims_rollback(fence) -> None:
    revision = fence.current_revision("trusted-operator", "disposable-ledger")
    fence.step(
        "trusted-operator", "disposable-ledger", expected_revision=revision, delta=6
    )
    fence.revoke("trusted-operator", "disposable-ledger", expected_revision=revision)
    assert fence.total("disposable-ledger") == 6
    assert fence.effect_count() == 1


def test_restart_cannot_restore_revoked_authority(fence) -> None:
    revision = fence.current_revision("trusted-operator", "disposable-ledger")
    fence.revoke("trusted-operator", "disposable-ledger", expected_revision=revision)
    restarted = TransactionalRevocationFence(fence.path)
    with pytest.raises(RevokedOperation):
        restarted.step(
            "trusted-operator", "disposable-ledger", expected_revision=revision, delta=1
        )
    assert restarted.total("disposable-ledger") == 0


def test_duplicate_operation_id_never_causes_second_effect(fence) -> None:
    revision = fence.current_revision("trusted-operator", "disposable-ledger")
    fence.step(
        "trusted-operator", "disposable-ledger", expected_revision=revision,
        delta=5, op_id="synthetic-operation-id"
    )
    with pytest.raises(sqlite3.IntegrityError):
        fence.step(
            "trusted-operator", "disposable-ledger", expected_revision=revision,
            delta=5, op_id="synthetic-operation-id"
        )
    assert fence.total("disposable-ledger") == 5


def test_stale_revocation_does_not_change_existing_grant(fence) -> None:
    with pytest.raises(RevokedOperation):
        fence.revoke("trusted-operator", "disposable-ledger", expected_revision=999)
    revision = fence.current_revision("trusted-operator", "disposable-ledger")
    assert revision == 0
    fence.step(
        "trusted-operator", "disposable-ledger", expected_revision=revision, delta=2
    )
    assert fence.total("disposable-ledger") == 2
