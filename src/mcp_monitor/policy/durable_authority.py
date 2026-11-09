"""Local durable signed ACL state for a bounded multi-process gateway pilot.

Multiple gateway processes on ONE trusted host consult the same SQLite file.
Reads do not cache decisions. This is not an authenticated network CDC feed,
not cross-host coordination, and not a rollback-proof distributed database.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import threading
from pathlib import Path
from typing import Any
from urllib.parse import quote

from mcp_monitor.policy.acl_guard import AccessDenied

_PURPOSE = b"mcp-local-authority-v1\x00"
_MAX_SNAPSHOT_BYTES = 524288


def _name(value: object) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 512 or "\x00" in value:
        raise AccessDenied("Invalid authoritative identity or resource")
    return value


def _snapshot(grants: dict[str, list[str]], revoked: list[list[str]]) -> str:
    """Reject malformed structures and produce a unique canonical representation."""
    if not isinstance(grants, dict) or not isinstance(revoked, list):
        raise AccessDenied("Invalid authoritative snapshot")
    clean: dict[str, list[str]] = {}
    for principal, resources in grants.items():
        _name(principal)
        if (
            not isinstance(resources, list)
            or len(resources) > 1024
            or any(not isinstance(item, str) for item in resources)
            or len(resources) != len(set(resources))
        ):
            raise AccessDenied("Invalid authoritative grant list")
        clean[principal] = sorted(_name(x) for x in resources)
    revocations: list[list[str]] = []
    for item in revoked:
        if not isinstance(item, list) or len(item) != 3:
            raise AccessDenied("Invalid authoritative session revocation")
        revocations.append([_name(x) for x in item])
    if len(revocations) != len(set(tuple(x) for x in revocations)):
        raise AccessDenied("Duplicate session revocation")
    encoded = json.dumps(
        {"grants": clean, "revoked": sorted(revocations)},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    if len(encoded.encode("utf-8")) > _MAX_SNAPSHOT_BYTES:
        raise AccessDenied("Authoritative snapshot exceeds size limit")
    return encoded


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise AccessDenied("Duplicate authoritative JSON key")
        obj[key] = value
    return obj


class SQLitePermissionAuthority:
    """Durable same-host permission and session-revocation checks.

    Provision database path and >=256-bit HMAC key only through trusted
    operator configuration. The key must not be stored in the database,
    printed, forwarded to a child, or supplied through MCP tool arguments.

    A trusted external minimum_revision can fence previously accepted signed
    snapshots after process restart. If both the database and this external
    checkpoint roll back, rollback cannot be detected by HMAC alone.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        key: bytes,
        minimum_revision: int = 0,
        timeout_seconds: float = 0.25,
    ) -> None:
        if not isinstance(path, str | Path) or not str(path):
            raise ValueError("Trusted database path required")
        if type(key) is not bytes or len(key) < 32:
            raise ValueError("Trusted HMAC key must contain at least 32 bytes")
        if type(minimum_revision) is not int or minimum_revision < 0:
            raise ValueError("Invalid trusted minimum revision")
        if type(timeout_seconds) not in (float, int) or not 0 < timeout_seconds <= 2:
            raise ValueError("Invalid database timeout")
        self._path = Path(path).resolve()
        self._key = key
        self._minimum_revision = minimum_revision
        self._highest_seen = minimum_revision
        self._timeout = float(timeout_seconds)
        self._lock = threading.RLock()

    def _mac(self, revision: int, encoded: str) -> str:
        message = _PURPOSE + str(revision).encode("ascii") + b"\x00" + encoded.encode("utf-8")
        return hmac.new(self._key, message, hashlib.sha256).hexdigest()

    def _reader(self) -> sqlite3.Connection:
        # Read-only mode is essential: an unavailable store MUST NOT be
        # recreated automatically as an empty, potentially permissive state.
        uri = "file:" + quote(str(self._path), safe="/") + "?mode=ro"
        return sqlite3.connect(uri, uri=True, timeout=self._timeout)

    def _writer(self) -> sqlite3.Connection:
        uri = "file:" + quote(str(self._path), safe="/") + "?mode=rw"
        return sqlite3.connect(uri, uri=True, timeout=self._timeout, isolation_level=None)

    def _load(self, db: sqlite3.Connection) -> tuple[int, dict[str, list[str]], list[list[str]]]:
        row = db.execute("SELECT revision, snapshot, mac FROM authority WHERE id = 1").fetchone()
        if (
            row is None
            or type(row[0]) is not int
            or row[0] < 0
            or not isinstance(row[1], str)
            or not isinstance(row[2], str)
            or len(row[2]) != 64
        ):
            raise AccessDenied("Missing or invalid authoritative snapshot")
        revision, encoded, tag = row
        if revision < self._highest_seen:
            raise AccessDenied("Authoritative snapshot rollback detected")
        if not hmac.compare_digest(tag, self._mac(revision, encoded)):
            raise AccessDenied("Authoritative snapshot authentication failed")
        if len(encoded.encode("utf-8")) > _MAX_SNAPSHOT_BYTES:
            raise AccessDenied("Authoritative snapshot size exceeded")
        try:
            state = json.loads(encoded, object_pairs_hook=_unique_pairs)
        except (ValueError, TypeError, RecursionError) as exc:
            raise AccessDenied("Invalid authoritative state encoding") from exc
        if not isinstance(state, dict) or set(state) != {"grants", "revoked"}:
            raise AccessDenied("Invalid authoritative state structure")
        canonical = _snapshot(state["grants"], state["revoked"])
        if canonical != encoded:
            raise AccessDenied("Noncanonical authoritative snapshot")
        self._highest_seen = revision
        return revision, state["grants"], state["revoked"]

    @classmethod
    def bootstrap(
        cls,
        path: str | Path,
        *,
        key: bytes,
        grants: dict[str, set[str]],
    ) -> SQLitePermissionAuthority:
        """Create one trusted local state, rejecting attempts to reinitialize it."""
        authority = cls(path, key=key)
        if not isinstance(grants, dict):
            raise AccessDenied("Invalid initial authoritative grants")
        initial: dict[str, list[str]] = {}
        for principal, resources in grants.items():
            _name(principal)
            if not isinstance(resources, set | frozenset):
                raise AccessDenied("Invalid initial grants")
            initial[principal] = sorted(_name(resource) for resource in resources)
        encoded = _snapshot(initial, [])
        db = sqlite3.connect(str(authority._path), timeout=authority._timeout, isolation_level=None)
        try:
            db.execute("BEGIN EXCLUSIVE")
            db.execute(
                "CREATE TABLE IF NOT EXISTS authority ("
                "id INTEGER PRIMARY KEY CHECK(id = 1), "
                "revision INTEGER NOT NULL, snapshot TEXT NOT NULL, mac TEXT NOT NULL)"
            )
            if db.execute("SELECT 1 FROM authority LIMIT 1").fetchone() is not None:
                raise AccessDenied("Authoritative store already initialized")
            db.execute(
                "INSERT INTO authority (id, revision, snapshot, mac) VALUES (1, 0, ?, ?)",
                (encoded, authority._mac(0, encoded)),
            )
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()
        return authority

    def _current(self) -> tuple[int, dict[str, list[str]], list[list[str]]]:
        with self._lock:
            try:
                db = self._reader()
                try:
                    return self._load(db)
                finally:
                    db.close()
            except AccessDenied:
                raise
            except Exception as exc:
                raise AccessDenied("Authoritative database unavailable") from exc

    @property
    def revision(self) -> int:
        return self._current()[0]

    def check(self, principal: str, resource_id: str) -> bool:
        """Return only an authenticated current decision, never cached grants."""
        _name(principal)
        _name(resource_id)
        _, grants, _ = self._current()
        return resource_id in grants.get(principal, [])

    def is_active(self, tenant: str, sid: str, jti: str) -> bool:
        """Phase 7 compatible trusted session-revocation callback."""
        _name(tenant)
        _name(sid)
        _name(jti)
        _, _, revoked = self._current()
        return [tenant, sid, jti] not in revoked

    def _update(
        self,
        expected_revision: int,
        *,
        principal: str | None = None,
        resource_id: str | None = None,
        allow: bool | None = None,
        revoke: tuple[str, str, str] | None = None,
    ) -> int:
        if type(expected_revision) is not int or expected_revision < 0:
            raise AccessDenied("Invalid expected authoritative revision")
        with self._lock:
            try:
                db = self._writer()
                try:
                    db.execute("BEGIN IMMEDIATE")
                    revision, grants, revoked = self._load(db)
                    if revision != expected_revision:
                        raise AccessDenied("Stale permission change revision")
                    if revoke is not None:
                        triple = [_name(item) for item in revoke]
                        if triple not in revoked:
                            revoked.append(triple)
                    else:
                        if allow is None or principal is None or resource_id is None:
                            raise AccessDenied("Incomplete authoritative permission change")
                        resources = set(grants.get(principal, []))
                        if allow:
                            resources.add(resource_id)
                        else:
                            resources.discard(resource_id)
                        grants[principal] = sorted(resources)
                    encoded = _snapshot(grants, revoked)
                    updated = revision + 1
                    db.execute(
                        "UPDATE authority SET revision = ?, snapshot = ?, mac = ? WHERE id = 1",
                        (updated, encoded, self._mac(updated, encoded)),
                    )
                    db.commit()
                    self._highest_seen = updated
                    return updated
                except Exception:
                    db.rollback()
                    raise
                finally:
                    db.close()
            except AccessDenied:
                raise
            except Exception as exc:
                raise AccessDenied("Authoritative update failed closed") from exc

    def set_grant(
        self, principal: str, resource_id: str, allowed: bool, *, expected_revision: int
    ) -> int:
        """Apply one operator-authenticated ordered change in a transaction."""
        _name(principal)
        _name(resource_id)
        if type(allowed) is not bool:
            raise AccessDenied("Invalid permission decision")
        return self._update(
            expected_revision, principal=principal, resource_id=resource_id, allow=allowed
        )

    def revoke_session(self, tenant: str, sid: str, jti: str, *, expected_revision: int) -> int:
        """Durably revoke a single session token triple for all local readers."""
        return self._update(expected_revision, revoke=(_name(tenant), _name(sid), _name(jti)))
