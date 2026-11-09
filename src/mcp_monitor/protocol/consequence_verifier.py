"""Independent, read-only consequence verification for a bounded MCP manifest edit.

This observer does not trust MCP JSON-RPC responses and never dispatches tools,
retries a side effect, or changes the durable gateway effect journal. A trusted
operator must provision the workspace and the expected exact operation.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

MAX_VERIFIED_MANIFEST_BYTES = 65536


class Consequence(str, Enum):
    VERIFIED_EFFECT = "VERIFIED_EFFECT"
    VERIFIED_NO_EFFECT = "VERIFIED_NO_EFFECT"
    UNEXPECTED_EFFECT = "UNEXPECTED_EFFECT"
    INDETERMINATE = "INDETERMINATE"


@dataclass(frozen=True)
class ManifestSnapshot:
    raw_sha256: str
    content: dict[str, Any]


@dataclass(frozen=True)
class ConsequenceReport:
    state: Consequence
    before_sha256: str
    observed_sha256: str | None
    reason: str


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate manifest JSON key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError("Nonfinite JSON numbers are forbidden")


def _read_manifest(root: Path) -> tuple[bytes, dict[str, Any]]:
    """Read an operator-selected regular file, rejecting links and oversized files."""
    if (
        not isinstance(root, Path)
        or not root.is_absolute()
        or root.is_symlink()
        or not root.is_dir()
        or root.resolve(strict=True) != root
    ):
        raise ValueError("Untrusted manifest workspace")
    path = root / "package.json"
    # Open without following a symlink; validate the opened inode, not just path.
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("Manifest is not a single-link regular file")
        if metadata.st_size > MAX_VERIFIED_MANIFEST_BYTES:
            raise ValueError("Manifest exceeds verification limit")
        with os.fdopen(os.dup(descriptor), "rb") as handle:
            raw = handle.read(MAX_VERIFIED_MANIFEST_BYTES + 1)
        if len(raw) > MAX_VERIFIED_MANIFEST_BYTES:
            raise ValueError("Manifest exceeds verification limit")
    finally:
        os.close(descriptor)
    decoded = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_strict_pairs,
        parse_constant=_reject_constant,
    )
    if not isinstance(decoded, dict) or not isinstance(decoded.get("dependencies"), dict):
        raise ValueError("Manifest dependencies unavailable")
    return raw, decoded


def capture_manifest(root: Path) -> ManifestSnapshot:
    raw, data = _read_manifest(root)
    return ManifestSnapshot(
        raw_sha256=hashlib.sha256(raw).hexdigest(),
        content=data,
    )


class ManifestConsequenceVerifier:
    """Compare independent file state with a pre-authorized exact transformation."""

    def __init__(
        self,
        root: Path,
        before: ManifestSnapshot,
        *,
        package: str,
        expected_previous: str,
        approved_version: str,
    ) -> None:
        if not all(
            isinstance(v, str) and bool(v)
            for v in (package, expected_previous, approved_version)
        ):
            raise ValueError("Trusted exact package/version approval required")
        if expected_previous == approved_version:
            raise ValueError("Expected effect must change the dependency")
        if before.content.get("dependencies", {}).get(package) != expected_previous:
            raise ValueError("Trusted preflight manifest does not match approved operation")
        self._root = root
        self._before = before
        self._package = package
        self._previous = expected_previous
        self._approved = approved_version

    def inspect(self) -> ConsequenceReport:
        """Read external state, ignoring all claims in the MCP server response."""
        try:
            raw, observed = _read_manifest(self._root)
            observed_hash = hashlib.sha256(raw).hexdigest()
        except (OSError, UnicodeError, ValueError, RecursionError) as exc:
            return ConsequenceReport(
                Consequence.INDETERMINATE,
                self._before.raw_sha256,
                None,
                f"Independent observation unavailable: {type(exc).__name__}",
            )

        if observed_hash == self._before.raw_sha256:
            return ConsequenceReport(
                Consequence.VERIFIED_NO_EFFECT,
                self._before.raw_sha256,
                observed_hash,
                "Observed file bytes exactly match trusted preflight snapshot",
            )

        approved_content = json.loads(
            json.dumps(self._before.content, sort_keys=True, allow_nan=False)
        )
        approved_content["dependencies"][self._package] = self._approved
        if observed == approved_content:
            return ConsequenceReport(
                Consequence.VERIFIED_EFFECT,
                self._before.raw_sha256,
                observed_hash,
                "Observed manifest contains only the exact approved dependency update",
            )
        return ConsequenceReport(
            Consequence.UNEXPECTED_EFFECT,
            self._before.raw_sha256,
            observed_hash,
            "Observed file differs from both preflight and authorized postcondition",
        )
