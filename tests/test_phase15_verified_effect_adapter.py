"""Phase 15: independent actual SQLite effects and acknowledgement-loss recovery."""

from __future__ import annotations

import sqlite3

import pytest

from mcp_monitor.protocol.effect_journal import EffectJournalError
from mcp_monitor.protocol.verified_effect_adapter import (
    LostAcknowledgement,
    VerifiedSQLiteEffectAdapter,
)


@pytest.fixture
def adapter(tmp_path):
    return VerifiedSQLiteEffectAdapter.bootstrap(
        tmp_path / "journal.sqlite", tmp_path / "downstream.sqlite"
    )


def test_authorized_local_effect_and_independent_inspection(adapter) -> None:
    op = adapter.propose("local-operator", "disposable-account", 5)
    assert adapter.independently_observed_effect(op) is None
    adapter.dispatch(op)
    assert adapter.balance("disposable-account") == 5
    assert adapter.independently_observed_effect(op) is True
    assert adapter.reconcile(op) == "COMMITTED"


def test_lost_ack_after_real_commit_recovered_without_second_effect(adapter) -> None:
    op = adapter.propose("local-operator", "disposable-account", 7)
    with pytest.raises(LostAcknowledgement) as info:
        adapter.dispatch(op, lose_ack=True)
    assert info.value.operation_id == op.operation_id
    assert adapter.balance("disposable-account") == 7
    assert adapter.journal.status(**adapter._key(op)) == "UNCERTAIN"

    restarted = VerifiedSQLiteEffectAdapter(adapter.journal._path, adapter.downstream_path)
    assert restarted.reconcile(op) == "COMMITTED"
    assert restarted.balance("disposable-account") == 7
    with pytest.raises(EffectJournalError, match="Duplicate"):
        restarted.dispatch(op)
    assert restarted.balance("disposable-account") == 7


def test_crash_after_reservation_retains_unknown_and_blocks_replay(adapter) -> None:
    op = adapter.propose("local-operator", "disposable-account", 4)
    adapter.journal.reserve(
        **adapter._key(op),
        arguments={"resource": op.resource, "delta": op.delta},
    )
    restarted = VerifiedSQLiteEffectAdapter(adapter.journal._path, adapter.downstream_path)
    assert restarted.reconcile(op) == "UNKNOWN"
    with pytest.raises(EffectJournalError, match="Duplicate"):
        restarted.dispatch(op)
    assert restarted.balance("disposable-account") == 0


def test_inconsistent_downstream_evidence_fails_closed(adapter) -> None:
    op = adapter.propose("local-operator", "disposable-account", 3)
    with pytest.raises(LostAcknowledgement):
        adapter.dispatch(op, lose_ack=True)
    with sqlite3.connect(adapter.downstream_path) as db:
        db.execute(
            "UPDATE committed_operations SET delta=99 WHERE operation_id=?",
            (op.operation_id,),
        )
    with pytest.raises(EffectJournalError, match="Conflicting"):
        adapter.reconcile(op)
    assert adapter.journal.status(**adapter._key(op)) == "UNCERTAIN"


def test_invalid_operation_denied_before_database_change(adapter) -> None:
    with pytest.raises(ValueError):
        adapter.propose("local-operator", "disposable-account", -1)
    with pytest.raises(ValueError):
        adapter.propose("local-operator", "disposable-account", True)
    assert adapter.balance("disposable-account") == 0


def test_missing_downstream_fails_without_pretending_success(adapter) -> None:
    op = adapter.propose("local-operator", "disposable-account", 2)
    adapter.downstream_path.unlink()
    with pytest.raises(sqlite3.Error):
        adapter.dispatch(op)
    assert adapter.journal.status(**adapter._key(op)) == "UNCERTAIN"
