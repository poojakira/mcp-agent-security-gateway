"""SHA-256 hash-chained immutable audit log.

Every MCP tool-call decision is recorded as an AuditEntry whose hash depends
on the previous entry's hash, creating a tamper-evident chain. If any
historical entry is modified, ``verify_chain()`` reports the first broken
index.

Integrity model
---------------
Without a key the chain is **tamper-evident but not tamper-proof**: because the
hash is a bare SHA-256 over public content, anyone who edits an entry can also
recompute every downstream hash and produce a self-consistent forged chain.

To make the chain **forgery-resistant**, supply a secret key via the
``MCP_AUDIT_HMAC_KEY`` environment variable or the ``AuditLog(..., hmac_key=...)``
constructor argument. When a key is present each entry hash is computed with
``hmac.new(key, msg, sha256)``. An attacker who edits an entry but does not
possess the key cannot recompute a valid HMAC, so ``verify_chain()`` detects
the forgery.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


def _canonical(data: dict[str, Any]) -> str:
    """Deterministic JSON serialization used for hashing.

    Uses ``json.dumps(..., sort_keys=True)`` so the hashed representation is
    stable across runs and matches a canonical persisted form (independent of
    dict insertion order or ``repr`` quirks of ``str(dict)``).
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


@dataclass
class AuditEntry:
    """Single entry in the hash-chained audit log."""

    entry_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    event_type: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    prev_hash: str = ""
    entry_hash: str = ""

    def compute_hash(self, hmac_key: bytes | None = None) -> str:
        """Compute the entry hash over prev_hash + timestamp + event_type + data.

        The ``data`` field is serialized with canonical JSON (``sort_keys``) so
        the digest is stable and matches the persisted representation.

        If ``hmac_key`` is provided, an HMAC-SHA256 is computed with that key so
        the hash cannot be forged without the key; otherwise a bare SHA-256 is
        used (tamper-evident, not tamper-proof).
        """
        content = self.prev_hash + str(self.timestamp) + self.event_type + _canonical(self.data)
        msg = content.encode("utf-8")
        if hmac_key is not None:
            return hmac.new(hmac_key, msg, hashlib.sha256).hexdigest()
        return hashlib.sha256(msg).hexdigest()


class AuditLog:
    """SHA-256 hash-chained immutable audit log.

    Parameters
    ----------
    log_file:
        Path to the append-only log file.
    hmac_key:
        Optional secret key for HMAC signing. If omitted, the value of the
        ``MCP_AUDIT_HMAC_KEY`` environment variable is used when set. When no
        key is available the chain is tamper-evident but not tamper-proof.
    """

    def __init__(self, log_file: str, hmac_key: str | bytes | None = None) -> None:
        self._log_file = Path(log_file)
        self._entries: list[AuditEntry] = []
        self._hmac_key: bytes | None = self._resolve_key(hmac_key)
        self._load()

    @staticmethod
    def _resolve_key(hmac_key: str | bytes | None) -> bytes | None:
        if hmac_key is None:
            env = os.environ.get("MCP_AUDIT_HMAC_KEY")
            if env:
                return env.encode("utf-8")
            return None
        if isinstance(hmac_key, str):
            return hmac_key.encode("utf-8")
        return hmac_key

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def append(self, event_type: str, data: dict[str, Any]) -> AuditEntry:
        """Append a new entry to the log, chaining its hash to the previous."""
        prev_hash = self._entries[-1].entry_hash if self._entries else "0" * 64

        entry = AuditEntry(
            event_type=event_type,
            data=data,
            prev_hash=prev_hash,
        )
        entry.entry_hash = entry.compute_hash(self._hmac_key)
        self._entries.append(entry)
        self._persist(entry)
        return entry

    def verify_chain(self) -> tuple[bool, int | None]:
        """Verify integrity of the full hash chain.

        Returns
        -------
        tuple of (intact: bool, broken_at_index: int | None)
            If intact is False, broken_at_index is the first index whose
            hash does not match the expected value.
        """
        for i, entry in enumerate(self._entries):
            expected_prev = self._entries[i - 1].entry_hash if i > 0 else "0" * 64
            if entry.prev_hash != expected_prev:
                return (False, i)
            expected_hash = entry.compute_hash(self._hmac_key)
            if entry.entry_hash != expected_hash:
                return (False, i)
        return (True, None)

    def tail(self, n: int = 10) -> list[AuditEntry]:
        """Return the last *n* entries."""
        return self._entries[-n:]

    def export_json(self) -> str:
        """Export the full log as a JSON string."""
        return json.dumps([asdict(entry) for entry in self._entries], indent=2)

    @property
    def entries(self) -> list[AuditEntry]:
        """Read-only access to all entries."""
        return list(self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    def _persist(self, entry: AuditEntry) -> None:
        """Append a single entry to the log file."""
        self._log_file.parent.mkdir(parents=True, exist_ok=True)
        with self._log_file.open("a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(entry)) + "\n")

    def _load(self) -> None:
        """Load existing entries from the log file."""
        if not self._log_file.exists():
            return
        with self._log_file.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                raw = json.loads(line)
                entry = AuditEntry(
                    entry_id=raw["entry_id"],
                    timestamp=raw["timestamp"],
                    event_type=raw["event_type"],
                    data=raw["data"],
                    prev_hash=raw["prev_hash"],
                    entry_hash=raw["entry_hash"],
                )
                self._entries.append(entry)
