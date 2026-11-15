"""Fail-closed, durable single-host side-effect intent journal for MCP tools.

An intent is committed BEFORE downstream dispatch. A crash or timeout leaves it
UNCERTAIN and it must not be automatically retried. Completion requires an independent observation stored atomically with its evidence. No journal can undo an action that already ran.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
import threading
import time
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
        if type(timeout_seconds) not in (float, int) or not 0 < timeout_seconds <= 2:
            raise ValueError("Invalid journal timeout")
        self._path = Path(path).absolute()
        self._timeout = float(timeout_seconds)
        self._lock = threading.RLock()

    @classmethod
    def bootstrap(cls, path: str | Path) -> DurableEffectJournal:
        store = cls(path)
        # Never adopt or overwrite an existing store, including an empty one.
        try:
            fd = os.open(store._path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        except OSError as exc:
            raise EffectJournalError("Fresh private journal path required") from exc
        db = store._open()
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
            db.execute(
                "CREATE TABLE observations ("
                "principal TEXT NOT NULL, server TEXT NOT NULL, tool TEXT NOT NULL, "
                "operation_key TEXT NOT NULL, evidence TEXT NOT NULL, "
                "PRIMARY KEY(principal, server, tool, operation_key))"
            )
            db.execute(
                "CREATE TABLE effect_bindings ("
                "principal TEXT NOT NULL, server TEXT NOT NULL, tool TEXT NOT NULL, "
                "operation_key TEXT NOT NULL, binding TEXT NOT NULL, "
                "PRIMARY KEY(principal, server, tool, operation_key))"
            )
            db.commit()
            # The containing directory entry must survive a local crash too.
            directory = os.open(store._path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()
        return store

    def _validate_file(self) -> None:
        metadata = self._path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o077
            or metadata.st_uid != os.getuid()
            or self._path.resolve(strict=True) != self._path
        ):
            raise EffectJournalError("Journal must be private, owned and single-link")

    def _open(self) -> sqlite3.Connection:
        self._validate_file()
        uri = "file:" + quote(str(self._path), safe="/") + "?mode=rw"
        db = sqlite3.connect(uri, uri=True, isolation_level=None, timeout=self._timeout)
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
        consequence_verifier: object = None,
    ) -> None:
        identity = (
            _label(principal, "principal"),
            _label(server, "server"),
            _label(tool, "tool"),
            _label(operation_key, "operation key"),
        )
        digest = _fingerprint(arguments)
        binding = None
        if consequence_verifier is not None:
            from mcp_monitor.protocol.consequence_verifier import (
                Consequence,
                ManifestConsequenceVerifier,
            )

            if type(consequence_verifier) is not ManifestConsequenceVerifier:
                raise EffectJournalError("Trusted consequence verifier required")
            if tool != "update_dependency" or digest != _fingerprint(
                consequence_verifier.arguments
            ):
                raise EffectJournalError("Observer does not match reserved effect")
            if consequence_verifier.inspect().state is not Consequence.VERIFIED_NO_EFFECT:
                raise EffectJournalError("Preflight state no longer current")
            binding = consequence_verifier.binding
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
                    if binding is not None:
                        db.execute(
                            "INSERT INTO effect_bindings VALUES (?, ?, ?, ?, ?)",
                            (*identity, binding),
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

    def mark_completed(self, *, principal: str, server: str, tool: str, operation_key: str) -> None:
        """A response or operator assertion alone cannot establish a consequence."""
        raise EffectJournalError("Independent consequence verification required")

    def reconcile_verified_effect(
        self,
        *,
        principal: str,
        server: str,
        tool: str,
        operation_key: str,
        verifier: object,
    ) -> None:
        """Record a bounded effect only after independent positive observation.

        A provider acknowledgment, gateway response, timeout, or local intent
        is not evidence of an external consequence. Indeterminate, no-effect,
        and unexpected-effect observations must remain UNCERTAIN and must
        never trigger an automatic retry.
        """
        from mcp_monitor.protocol.consequence_verifier import (
            Consequence,
            ManifestConsequenceVerifier,
        )

        if type(verifier) is not ManifestConsequenceVerifier:
            raise EffectJournalError("Trusted independent consequence verifier required")
        if tool != "update_dependency":
            raise EffectJournalError("Unsupported reconciliation tool")
        expected = _fingerprint(
            {
                "package": verifier._package,
                "version": verifier._approved,
                "expected_previous": verifier._previous,
            }
        )
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
                    # Hold the write lock across observation and state transition.
                    # Concurrent reconcilers cannot both accept the same intent.
                    db.execute("BEGIN IMMEDIATE")
                    row = db.execute(
                        "SELECT argument_hash, status FROM effects "
                        "WHERE principal=? AND server=? AND tool=? AND operation_key=?",
                        identity,
                    ).fetchone()
                    if row != (expected, "UNCERTAIN"):
                        raise EffectJournalError("Observer does not match reserved effect")
                    bound = db.execute(
                        "SELECT binding FROM effect_bindings WHERE principal=? AND server=? "
                        "AND tool=? AND operation_key=?",
                        identity,
                    ).fetchone()
                    if bound != (verifier.binding,):
                        raise EffectJournalError(
                            "Observer does not match reserved resource/preflight"
                        )
                    report = verifier.inspect()
                    if report.state is not Consequence.VERIFIED_EFFECT:
                        raise EffectJournalError("External effect not independently verified")
                    if (
                        not isinstance(report.before_sha256, str)
                        or not isinstance(report.observed_sha256, str)
                        or len(report.before_sha256) != 64
                        or len(report.observed_sha256) != 64
                        or report.before_sha256 == report.observed_sha256
                        or any(
                            c not in "0123456789abcdef"
                            for c in report.before_sha256 + report.observed_sha256
                        )
                    ):
                        raise EffectJournalError("Invalid independent observation hashes")
                    evidence = json.dumps(
                        {
                            "observer": "manifest-v1",
                            "workspace": str(verifier._root),
                            "before_sha256": report.before_sha256,
                            "observed_sha256": report.observed_sha256,
                            "observed_at_ns": time.time_ns(),
                            "consistency": "point-in-time local file observation; not immutable state",
                            "argument_hash": expected,
                        },
                        sort_keys=True,
                        allow_nan=False,
                    )
                    db.execute(
                        "INSERT INTO observations VALUES (?, ?, ?, ?, ?)",
                        (*identity, evidence),
                    )
                    updated = db.execute(
                        "UPDATE effects SET status='COMPLETED' "
                        "WHERE principal=? AND server=? AND tool=? AND operation_key=? "
                        "AND argument_hash=? AND status='UNCERTAIN'",
                        (*identity, expected),
                    )
                    if updated.rowcount != 1:
                        raise EffectJournalError("Effect changed during reconciliation")
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

    def status(self, *, principal: str, server: str, tool: str, operation_key: str) -> str | None:
        identity = (
            _label(principal, "principal"),
            _label(server, "server"),
            _label(tool, "tool"),
            _label(operation_key, "operation key"),
        )
        try:
            self._validate_file()
            uri = "file:" + quote(str(self._path), safe="/") + "?mode=ro"
            with sqlite3.connect(uri, uri=True, timeout=self._timeout) as db:
                record = db.execute(
                    "SELECT status FROM effects "
                    "WHERE principal=? AND server=? AND tool=? AND operation_key=?",
                    identity,
                ).fetchone()
            if record is None:
                return None
            if record[0] == "COMPLETED":
                self.evidence(
                    principal=principal, server=server, tool=tool, operation_key=operation_key
                )
            if record[0] not in ("UNCERTAIN", "COMPLETED"):
                raise EffectJournalError("Effect journal state corrupted")
            return record[0]
        except EffectJournalError:
            raise
        except Exception as exc:
            raise EffectJournalError("Effect journal unavailable") from exc

    def evidence(self, *, principal: str, server: str, tool: str, operation_key: str) -> dict:
        """Read durable observation provenance; legacy unproven completions fail closed."""
        identity = tuple(_label(v, "identity") for v in (principal, server, tool, operation_key))
        try:
            self._validate_file()
            uri = "file:" + quote(str(self._path), safe="/") + "?mode=ro"
            with sqlite3.connect(uri, uri=True, timeout=self._timeout) as db:
                row = db.execute(
                    "SELECT evidence FROM observations WHERE principal=? AND server=? "
                    "AND tool=? AND operation_key=?",
                    identity,
                ).fetchone()
            if row is None:
                raise EffectJournalError("Independent observation evidence missing")
            evidence = json.loads(row[0])
            if not isinstance(evidence, dict) or evidence.get("observer") != "manifest-v1":
                raise EffectJournalError("Invalid observation evidence")
            return evidence
        except EffectJournalError:
            raise
        except Exception as exc:
            raise EffectJournalError("Observation evidence unavailable") from exc
