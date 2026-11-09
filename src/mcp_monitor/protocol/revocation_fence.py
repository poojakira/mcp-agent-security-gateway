"""Single-host cooperative revocation fence for a bounded MCP file effect.

A trusted operator owns this SQLite authority and provisions the principal.
A protected effect holds SQLite's BEGIN IMMEDIATE transaction until its file
replacement is complete. A concurrent revocation cannot become effective
between final authorization and the physical effect commit.

This is *not* an OS sandbox, an external identity provider, a network lock, an
exactly-once guarantee, or a cross-host consensus mechanism. All writers and
revokers must cooperate and use the same trusted local authority database.
"""

from __future__ import annotations

import os
import sqlite3
import stat
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator
from urllib.parse import quote


class RevocationFenceError(ValueError):
    """Fail-closed identity, authority or revocation boundary."""


def _principal(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 128
        or not value.isascii()
        or not all(ch.isalnum() or ch in "_.:-" for ch in value)
    ):
        raise RevocationFenceError("Invalid trusted operator principal")
    return value


class RevocationFence:
    """A single-process-adapter guard coordinated by protected SQLite storage."""

    def __init__(self, path: Path, *, timeout_seconds: float = 0.5) -> None:
        if (
            not isinstance(path, Path)
            or not path.is_absolute()
            or path.is_symlink()
            or not path.is_file()
        ):
            raise RevocationFenceError("Existing absolute authority database required")
        if (
            not isinstance(timeout_seconds, int | float)
            or isinstance(timeout_seconds, bool)
            or not 0 < timeout_seconds <= 5
        ):
            raise RevocationFenceError("Invalid authority lock timeout")
        metadata = path.stat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or (metadata.st_mode & 0o077) != 0
        ):
            raise RevocationFenceError("Authority database must be private and single-link")
        self._path = path.resolve(strict=True)
        self._timeout = float(timeout_seconds)

    @classmethod
    def bootstrap(cls, path: Path, *, principal: str) -> RevocationFence:
        """One-time trusted local operator provisioning; never run on MCP input."""
        identity = _principal(principal)
        if not isinstance(path, Path) or not path.is_absolute() or path.exists():
            raise RevocationFenceError("A fresh absolute authority file is required")
        if not path.parent.is_dir() or path.parent.is_symlink():
            raise RevocationFenceError("Trusted authority directory required")
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
        os.chmod(path, 0o600)
        gate = cls(path)
        try:
            with gate._connect() as db:
                db.execute("PRAGMA journal_mode=WAL")
                db.execute(
                    "CREATE TABLE capability ("
                    "principal TEXT PRIMARY KEY NOT NULL, "
                    "allowed INTEGER NOT NULL CHECK(allowed IN (0,1)), "
                    "epoch INTEGER NOT NULL CHECK(epoch >= 0))"
                )
                db.execute(
                    "INSERT INTO capability(principal, allowed, epoch) VALUES(?,1,0)",
                    (identity,),
                )
        except sqlite3.Error as exc:
            raise RevocationFenceError("Could not bootstrap authority database") from exc
        return gate

    def _connect(self) -> sqlite3.Connection:
        uri = "file:" + quote(str(self._path), safe="/") + "?mode=rw"
        db = sqlite3.connect(
            uri,
            uri=True,
            isolation_level=None,
            timeout=self._timeout,
        )
        db.execute("PRAGMA synchronous=FULL")
        return db

    @contextmanager
    def authorize_effect(self, principal: str) -> Iterator[int]:
        """Serialize authority check through the actual protected file commit.

        Revocation may be *requested* while an effect is in progress. It cannot
        *complete* until this transaction ends. Any revocation already committed
        before we acquire the lock prevents the effect.
        """
        identity = _principal(principal)
        try:
            db = self._connect()
        except sqlite3.Error as exc:
            raise RevocationFenceError("Revocation authority unavailable") from exc
        try:
            try:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute(
                    "SELECT allowed,epoch FROM capability WHERE principal=?",
                    (identity,),
                ).fetchone()
                if row is None or row[0] != 1 or type(row[1]) is not int or row[1] < 0:
                    raise RevocationFenceError("Operator authorization revoked or unavailable")
                yield row[1]
                db.commit()
            except Exception:
                db.rollback()
                raise
        except sqlite3.Error as exc:
            raise RevocationFenceError("Revocation authority unavailable") from exc
        finally:
            db.close()

    def revoke(self, *, principal: str) -> int:
        """Trusted operator action: permanently revoke this laboratory principal.

        This method is intentionally not exposed through MCP tool arguments.
        The return value is the durable revocation epoch, not a rollback token.
        """
        identity = _principal(principal)
        try:
            with self._connect() as db:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute(
                    "SELECT allowed,epoch FROM capability WHERE principal=?", (identity,)
                ).fetchone()
                if row is None:
                    raise RevocationFenceError("Principal not provisioned")
                if row[0] == 1:
                    db.execute(
                        "UPDATE capability SET allowed=0,epoch=epoch+1 WHERE principal=?",
                        (identity,),
                    )
                new_epoch = db.execute(
                    "SELECT epoch FROM capability WHERE principal=?", (identity,)
                ).fetchone()
                assert new_epoch is not None
                return int(new_epoch[0])
        except sqlite3.Error as exc:
            raise RevocationFenceError("Revocation authority unavailable") from exc

    def status(self, *, principal: str) -> tuple[bool, int]:
        identity = _principal(principal)
        try:
            with self._connect() as db:
                row = db.execute(
                    "SELECT allowed,epoch FROM capability WHERE principal=?", (identity,)
                ).fetchone()
            if row is None or row[0] not in (0, 1) or type(row[1]) is not int:
                raise RevocationFenceError("Invalid or unknown authority state")
            return (row[0] == 1, row[1])
        except sqlite3.Error as exc:
            raise RevocationFenceError("Revocation authority unavailable") from exc
