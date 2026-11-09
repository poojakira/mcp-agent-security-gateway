"""Independent SQLite consequence evidence for a disposable local effect adapter.

This adapter deliberately uses a DIFFERENT SQLite store for downstream state
than the intent journal. It demonstrates conservative unknown-outcome handling,
not distributed exactly-once execution or protection from an OS-level attacker.
No model APIs, credentials, network requests, or production systems are used.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from dataclasses import dataclass
from pathlib import Path

from mcp_monitor.protocol.effect_journal import DurableEffectJournal, EffectJournalError


class LostAcknowledgement(RuntimeError):
    """The downstream transaction committed, but confirmation did not arrive."""

    def __init__(self, operation_id: str):
        self.operation_id = operation_id
        super().__init__("Acknowledgement lost; outcome is uncertain")


@dataclass(frozen=True)
class EffectRequest:
    operation_id: str
    principal: str
    resource: str
    delta: int


class VerifiedSQLiteEffectAdapter:
    """Operator-controlled transaction demonstration with independent state reads."""

    def __init__(self, journal_path: str | Path, downstream_path: str | Path):
        self.journal = DurableEffectJournal(journal_path)
        self.downstream_path = Path(downstream_path)
        if not self.downstream_path.is_file():
            raise ValueError("Downstream database must be provisioned beforehand")

    @classmethod
    def bootstrap(cls, journal_path: str | Path, downstream_path: str | Path):
        DurableEffectJournal.bootstrap(journal_path)
        with sqlite3.connect(downstream_path) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            db.execute(
                "CREATE TABLE IF NOT EXISTS balances ("
                "resource TEXT PRIMARY KEY, amount INTEGER NOT NULL)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS committed_operations ("
                "operation_id TEXT PRIMARY KEY, principal TEXT NOT NULL, "
                "resource TEXT NOT NULL, delta INTEGER NOT NULL, evidence_hash TEXT NOT NULL)"
            )
        return cls(journal_path, downstream_path)

    @staticmethod
    def _digest(op: EffectRequest) -> str:
        payload = json.dumps(
            [op.operation_id, op.principal, op.resource, op.delta],
            separators=(",", ":"),
        ).encode()
        return hashlib.sha256(payload).hexdigest()

    @staticmethod
    def propose(principal: str, resource: str, delta: int) -> EffectRequest:
        if (
            not isinstance(principal, str)
            or not principal
            or not isinstance(resource, str)
            or not resource
            or type(delta) is not int
            or not 1 <= delta <= 100
        ):
            raise ValueError("Invalid bounded effect request")
        return EffectRequest(str(uuid.uuid4()), principal, resource, delta)

    def _key(self, op: EffectRequest) -> dict[str, str]:
        return {
            "principal": op.principal,
            "server": "local-sqlite",
            "tool": "credit",
            "operation_key": op.operation_id,
        }

    def dispatch(self, op: EffectRequest, *, lose_ack: bool = False) -> None:
        """Reserve before the trusted adapter touches downstream state."""
        self.journal.reserve(
            **self._key(op),
            arguments={"resource": op.resource, "delta": op.delta},
        )
        with sqlite3.connect(self.downstream_path, isolation_level=None) as db:
            db.execute("PRAGMA synchronous=FULL")
            try:
                db.execute("BEGIN IMMEDIATE")
                exists = db.execute(
                    "SELECT 1 FROM committed_operations WHERE operation_id=?",
                    (op.operation_id,),
                ).fetchone()
                if exists:
                    raise EffectJournalError("Existing downstream operation identifier")
                db.execute(
                    "INSERT INTO balances(resource,amount) VALUES (?,?) "
                    "ON CONFLICT(resource) DO UPDATE SET amount=amount+excluded.amount",
                    (op.resource, op.delta),
                )
                db.execute(
                    "INSERT INTO committed_operations VALUES (?,?,?,?,?)",
                    (
                        op.operation_id,
                        op.principal,
                        op.resource,
                        op.delta,
                        self._digest(op),
                    ),
                )
                db.commit()
            except Exception:
                db.rollback()
                raise
        if lose_ack:
            raise LostAcknowledgement(op.operation_id)
        self.journal.mark_completed(**self._key(op))

    def independently_observed_effect(self, op: EffectRequest) -> bool | None:
        """Return true only on matching committed evidence; never infer from response."""
        with sqlite3.connect(
            f"file:{self.downstream_path.as_posix()}?mode=ro", uri=True
        ) as db:
            entry = db.execute(
                "SELECT principal,resource,delta,evidence_hash "
                "FROM committed_operations WHERE operation_id=?",
                (op.operation_id,),
            ).fetchone()
        if entry is None:
            return None
        if entry != (op.principal, op.resource, op.delta, self._digest(op)):
            raise EffectJournalError("Conflicting independent downstream evidence")
        return True

    def reconcile(self, op: EffectRequest) -> str:
        status = self.journal.status(**self._key(op))
        if status == "COMPLETED":
            return "COMMITTED"
        if status != "UNCERTAIN":
            raise EffectJournalError("No reserved uncertain operation")
        observed = self.independently_observed_effect(op)
        if observed is None:
            return "UNKNOWN"
        self.journal.mark_completed(**self._key(op))
        return "COMMITTED"

    def balance(self, resource: str) -> int:
        with sqlite3.connect(
            f"file:{self.downstream_path.as_posix()}?mode=ro", uri=True
        ) as db:
            row = db.execute(
                "SELECT amount FROM balances WHERE resource=?", (resource,)
            ).fetchone()
        return row[0] if row else 0
