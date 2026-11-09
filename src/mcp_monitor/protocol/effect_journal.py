"""Fail-closed, durable single-host side-effect intent journal for MCP tools.

An intent is committed BEFORE downstream dispatch. A crash or timeout leaves it
UNCERTAIN and it must not be automatically retried. Completion records only
a valid, inspected success. No journal can undo an action that already ran.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
from pathlib import Path
from urllib.parse import quote

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")


class EffectJournalError(ValueError):
    """Operation cannot be safely reserved or completion is uncertain."""


def _label(value: object, name: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise EffectJournalError(f"Invalid {name}")
    return value


def _fingerprint(arguments: object) -> str:
    try:
        canonical = json.dumps(
            arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        )
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise EffectJournalError("Invalid operation arguments") from exc
    if len(canonical.encode("utf-8")) > 65536:
        raise EffectJournalError("Operation arguments too large")
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class DurableEffectJournal:
    """No replay: the first request reserves a key; every reuse is denied.

    Only a trusted operator may bootstrap the database, configure its path,
    inspect ambiguous entries, and perform explicit manual reconciliation.
    Uses SQLite WAL plus FULL synchronous commits. A missing/corrupt/locked
    database fails closed; normal runtime never recreates the store.
    """

    def __init__(self, path: str | Path, *, timeout_seconds: float = 0.2) -> None:
        if not isinstance(path, str | Path) or not str(path):
            raise ValueError("Trusted effect database path required")
        if (
            type(timeout_seconds) not in (float, int)
            or not 0 < timeout_seconds <= 2
        ):
            raise ValueError("Invalid journal timeout")
        self._path = Path(path).resolve()
        self._timeout = float(timeout_seconds)
        self._lock = threading.RLock()

    @classmethod
    def bootstrap(cls, path: str | Path) -> DurableEffectJournal:
        store = cls(path)
        db = sqlite3.connect(str(store._path), isolation_level=None, timeout=store._timeout)
        try:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "CREATE TABLE IF NOT EXISTS effects ("
                "principal TEXT NOT NULL, server TEXT NOT NULL, tool TEXT NOT NULL, "
                "operation_key TEXT NOT NULL, argument_hash TEXT NOT NULL, "
                "status TEXT NOT NULL CHECK(status IN ('UNCERTAIN', 'COMPLETED')), "
                "PRIMARY KEY(principal, server, tool, operation_key))"
            )
            if db.execute("SELECT 1 FROM effects LIMIT 1").fetchone() is not None:
                raise EffectJournalError("Effect journal already initialized")
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()
        return store

    def _open(self) -> sqlite3.Connection:
        uri = "file:" + quote(str(self._path), safe="/") + "?mode=rw"
        db = sqlite3.connect(
            uri, uri=True, isolation_level=None, timeout=self._timeout
        )
        db.execute("PRAGMA synchronous=FULL")
        return db

    def reserve(
        self,
        *,
        principal: str,
        server: str,
        tool: str,
        operation_key: str,
        arguments: object,
    ) -> None:
        identity = (
            _label(principal, "principal"),
            _label(server, "server"),
            _label(tool, "tool"),
            _label(operation_key, "operation key"),
        )
        digest = _fingerprint(arguments)
        with self._lock:
            try:
                db = self._open()
                try:
                    db.execute("BEGIN IMMEDIATE")
                    existing = db.execute(
                        "SELECT argument_hash, status FROM effects "
                        "WHERE principal=? AND server=? AND tool=? AND operation_key=?",
                        identity,
                    ).fetchone()
                    if existing is not None:
                        raise EffectJournalError("Duplicate or unresolved operation denied")
                    db.execute(
                        "INSERT INTO effects VALUES (?, ?, ?, ?, ?, 'UNCERTAIN')",
                        (*identity, digest),
                    )
                    db.commit()
                except Exception:
                    db.rollback()
                    raise
                finally:
                    db.close()
            except EffectJournalError:
                raise
            except Exception as exc:
                raise EffectJournalError("Effect journal unavailable") from exc

    def mark_completed(
        self, *, principal: str, server: str, tool: str, operation_key: str
    ) -> None:
        identity = (
            _label(principal, "principal"),
            _label(server, "server"),
            _label(tool, "tool"),
            _label(operation_key, "operation key"),
        )
        with self._lock:
            try:
                db = self._open()
                try:
                    db.execute("BEGIN IMMEDIATE")
                    updated = db.execute(
                        "UPDATE effects SET status='COMPLETED' "
                        "WHERE principal=? AND server=? AND tool=? AND operation_key=? "
                        "AND status='UNCERTAIN'",
                        identity,
                    )
                    if updated.rowcount != 1:
                        raise EffectJournalError("No uncertain operation to complete")
                    db.commit()
                except Exception:
                    db.rollback()
                    raise
                finally:
                    db.close()
            except EffectJournalError:
                raise
            except Exception as exc:
                raise EffectJournalError("Effect completion journal unavailable") from exc

    def status(
        self, *, principal: str, server: str, tool: str, operation_key: str
    ) -> str | None:
        identity = (
            _label(principal, "principal"),
            _label(server, "server"),
            _label(tool, "tool"),
            _label(operation_key, "operation key"),
        )
        try:
            uri = "file:" + quote(str(self._path), safe="/") + "?mode=ro"
            with sqlite3.connect(uri, uri=True, timeout=self._timeout) as db:
                record = db.execute(
                    "SELECT status FROM effects "
                    "WHERE principal=? AND server=? AND tool=? AND operation_key=?",
                    identity,
                ).fetchone()
            if record is None:
                return None
            if record[0] not in ("UNCERTAIN", "COMPLETED"):
                raise EffectJournalError("Effect journal state corrupted")
            return record[0]
        except EffectJournalError:
            raise
        except Exception as exc:
            raise EffectJournalError("Effect journal unavailable") from exc
