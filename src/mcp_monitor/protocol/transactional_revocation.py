"""A local transaction fence for authorization revisions and disposable effects.

The authoritative grant and the protected effect share ONE SQLite transaction
domain, so a permission revocation and a new effect are serialized. No claim
is made that this fences arbitrary external MCP servers or remote services.
"""

from __future__ import annotations

import sqlite3
import uuid
from pathlib import Path


class RevokedOperation(PermissionError):
    """No protected state was committed because authority was not current."""


class TransactionalRevocationFence:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        if not self.path.is_file():
            raise ValueError("Trusted fence database not provisioned")

    @classmethod
    def bootstrap(cls, path: str | Path, *, principal: str, resource: str):
        if not principal or not resource:
            raise ValueError("Trusted principal and resource required")
        with sqlite3.connect(path, isolation_level=None) as db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "CREATE TABLE IF NOT EXISTS grants ("
                "principal TEXT, resource TEXT, revision INTEGER NOT NULL, "
                "active INTEGER NOT NULL CHECK(active IN (0,1)), "
                "PRIMARY KEY(principal,resource))"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS protected_effects ("
                "op_id TEXT PRIMARY KEY, principal TEXT NOT NULL, resource TEXT NOT NULL, "
                "revision INTEGER NOT NULL, delta INTEGER NOT NULL)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS totals ("
                "resource TEXT PRIMARY KEY, amount INTEGER NOT NULL)"
            )
            db.execute(
                "INSERT INTO grants VALUES (?,?,0,1)", (principal, resource)
            )
            db.commit()
        return cls(path)

    def _open(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=2, isolation_level=None)
        db.execute("PRAGMA synchronous=FULL")
        return db

    def current_revision(self, principal: str, resource: str) -> int:
        with self._open() as db:
            record = db.execute(
                "SELECT revision FROM grants WHERE principal=? AND resource=?",
                (principal, resource),
            ).fetchone()
        if record is None:
            raise RevokedOperation("Missing authenticated local authority record")
        return int(record[0])

    def revoke(self, principal: str, resource: str, *, expected_revision: int) -> int:
        with self._open() as db:
            try:
                db.execute("BEGIN IMMEDIATE")
                updated = db.execute(
                    "UPDATE grants SET revision=revision+1, active=0 "
                    "WHERE principal=? AND resource=? AND revision=? AND active=1",
                    (principal, resource, expected_revision),
                )
                if updated.rowcount != 1:
                    raise RevokedOperation("Revocation rejected: stale authority revision")
                db.commit()
                return expected_revision + 1
            except Exception:
                db.rollback()
                raise

    def step(
        self,
        principal: str,
        resource: str,
        *,
        expected_revision: int,
        delta: int,
        op_id: str | None = None,
    ) -> str:
        if (
            type(expected_revision) is not int
            or expected_revision < 0
            or type(delta) is not int
            or not 1 <= delta <= 100
        ):
            raise ValueError("Invalid trusted step")
        operation = op_id or str(uuid.uuid4())
        with self._open() as db:
            try:
                db.execute("BEGIN IMMEDIATE")
                grant = db.execute(
                    "SELECT revision,active FROM grants WHERE principal=? AND resource=?",
                    (principal, resource),
                ).fetchone()
                if grant != (expected_revision, 1):
                    raise RevokedOperation("Current transactional authorization fence denied effect")
                db.execute(
                    "INSERT INTO protected_effects VALUES (?,?,?,?,?)",
                    (operation, principal, resource, expected_revision, delta),
                )
                db.execute(
                    "INSERT INTO totals VALUES (?,?) "
                    "ON CONFLICT(resource) DO UPDATE SET amount=amount+excluded.amount",
                    (resource, delta),
                )
                db.commit()
                return operation
            except Exception:
                db.rollback()
                raise

    def total(self, resource: str) -> int:
        with self._open() as db:
            row = db.execute(
                "SELECT amount FROM totals WHERE resource=?", (resource,)
            ).fetchone()
        return row[0] if row else 0

    def effect_count(self) -> int:
        with self._open() as db:
            return int(db.execute("SELECT COUNT(*) FROM protected_effects").fetchone()[0])
