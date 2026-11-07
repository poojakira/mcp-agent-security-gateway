"""ACL-scoped retrieval and permission-change guard for MCP integrations.

The operator supplies authenticated user identity and trusted ACL snapshots.
Agent-supplied user IDs, ACLs, or search filters are never authorization inputs.
CDC events must come from an authenticated, ordered feed. Loss of order fails closed.
This is an in-process reference implementation; no external CDC or index connector
is bundled, and no millisecond propagation guarantee is made.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from threading import RLock
from typing import Any


class AccessDenied(Exception):
    """Permission denied or ACL state cannot be trusted."""


@dataclass(frozen=True)
class PermissionChange:
    sequence: int
    principal: str
    resource_id: str
    allowed: bool


class ACLGuard:
    """In-memory trusted ACL snapshot with ordered, fail-closed revocations."""

    def __init__(
        self,
        grants: dict[str, set[str]],
        *,
        sequence: int = 0,
    ) -> None:
        if sequence < 0 or not isinstance(sequence, int):
            raise ValueError("Invalid starting sequence")
        self._lock = RLock()
        self._grants = {user: frozenset(resources) for user, resources in grants.items()}
        self._sequence = sequence
        self._healthy = True

    def _require_healthy(self) -> None:
        if not self._healthy:
            raise AccessDenied("ACL feed is stale or out of order; deny until resynchronized")

    def allowed_resources(self, principal: str) -> frozenset[str]:
        """Get trusted allowed IDs, never from user/agent-provided filters."""
        with self._lock:
            self._require_healthy()
            if not isinstance(principal, str) or not principal:
                raise AccessDenied("Missing authenticated identity")
            return self._grants.get(principal, frozenset())

    def check(self, principal: str, resource_id: str) -> None:
        """Deny by default, including absent or malformed identities/resources."""
        if not isinstance(resource_id, str) or not resource_id:
            raise AccessDenied("Missing resource identity")
        if resource_id not in self.allowed_resources(principal):
            raise AccessDenied("Resource not authorized")

    def apply_change(self, change: PermissionChange) -> None:
        """Apply an authenticated ordered CDC event; reject gaps and replays.

        The caller must authenticate the change feed before invoking this method.
        """
        with self._lock:
            self._require_healthy()
            if (
                not isinstance(change.sequence, int)
                or change.sequence != self._sequence + 1
                or not change.principal
                or not change.resource_id
            ):
                self._healthy = False
                raise AccessDenied("Out-of-order or malformed permission change")
            grants = set(self._grants.get(change.principal, frozenset()))
            if change.allowed:
                grants.add(change.resource_id)
            else:
                grants.discard(change.resource_id)
            self._grants[change.principal] = frozenset(grants)
            self._sequence = change.sequence

    def replace_snapshot(self, grants: dict[str, set[str]], *, sequence: int) -> None:
        """Trusted full resynchronization after missed/out-of-order CDC events."""
        with self._lock:
            if not isinstance(sequence, int) or sequence < self._sequence:
                raise AccessDenied("Snapshot sequence must not move backwards")
            self._grants = {user: frozenset(resources) for user, resources in grants.items()}
            self._sequence = sequence
            self._healthy = True

    def authorized_search(
        self,
        principal: str,
        query: str,
        search: Callable[[str, frozenset[str]], list[dict[str, Any]]],
    ) -> list[dict[str, Any]]:
        """Enforce search scope before retrieval, then recheck each returned ID.

        The search adapter MUST enforce the allowed ID filter at the datastore;
        post-filtering alone is insufficient for secure vector similarity search.
        No query embeddings, counts, or snippets should expose forbidden IDs.
        """
        with self._lock:
            self._require_healthy()
            allowed = self.allowed_resources(principal)
            if not allowed:
                return []
            # Lock prevents same-process CDC revocations from racing a retrieval.
            results = search(query, allowed)
            if not isinstance(results, list):
                raise AccessDenied("Invalid search response")
            safe: list[dict[str, Any]] = []
            for item in results:
                if not isinstance(item, dict):
                    raise AccessDenied("Invalid search hit")
                resource_id = item.get("resource_id")
                if not isinstance(resource_id, str) or resource_id not in allowed:
                    # Do not return a partially trusted response.
                    raise AccessDenied("Search backend returned unauthorized data")
                self.check(principal, resource_id)
                safe.append(item)
            return safe
