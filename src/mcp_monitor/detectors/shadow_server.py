"""Shadow MCP server detection.

Flags tool calls targeting unregistered or untrusted MCP servers, preventing
lateral movement via rogue tool endpoints that were never approved by the
operator.
"""

from __future__ import annotations

import time
from typing import Any


class ShadowServerDetector:
    """Detects tool calls to unexpected/unregistered MCP servers."""

    def __init__(self, allowed_servers: set[str]) -> None:
        self._allowed: set[str] = set(allowed_servers)
        # server_id -> {capabilities, registered_at, call_count}
        self._registry: dict[str, dict[str, Any]] = {}
        # Calls observed from allowed-but-not-capability-registered servers.
        self._unregistered_calls: dict[str, int] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def register_server(self, server_id: str, capabilities: list[str]) -> None:
        """Register a server as known/trusted with its declared capabilities."""
        self._allowed.add(server_id)
        self._registry[server_id] = {
            "capabilities": capabilities,
            "registered_at": time.time(),
            "call_count": 0,
        }

    def detect(self, tool_call: dict[str, Any]) -> tuple[bool, str]:
        """Determine whether a tool call targets an unregistered server.

        Parameters
        ----------
        tool_call:
            Must contain a ``"server_id"`` field.

        Returns
        -------
        tuple of (is_shadow: bool, reason: str)
        """
        server_id = tool_call.get("server_id")
        if server_id is None:
            return (True, "tool_call missing server_id field")

        if server_id not in self._allowed:
            return (True, f"server '{server_id}' is not registered")

        # Track usage
        if server_id in self._registry:
            self._registry[server_id]["call_count"] += 1
        else:
            # Allowed but not capability-registered: track separately so trust
            # scoring can treat unproven volume as a risk signal.
            self._unregistered_calls[server_id] = self._unregistered_calls.get(server_id, 0) + 1

        # Check capability mismatch
        tool_name: str = tool_call.get("name", "")
        capability_prefix = tool_name.split(".")[0] if "." in tool_name else ""
        if (
            capability_prefix
            and server_id in self._registry
            and self._registry[server_id]["capabilities"]
        ):
            caps = self._registry[server_id]["capabilities"]
            if capability_prefix not in caps and tool_name not in caps:
                return (
                    True,
                    f"server '{server_id}' not registered for capability '{capability_prefix}'",
                )

        return (False, "")

    def score_server_trust(self, server_id: str) -> int:
        """Return a trust score 0-100 for a given server.

        Trust is grounded in *provenance* (was the server known/approved during
        the initialization phase?), not in raw call volume. A high volume of
        calls from an unknown or unregistered server is treated as a RISK
        signal that *lowers* trust rather than raising it - an unapproved
        endpoint should not be able to bootstrap trust simply by making many
        requests.

        Scoring:
        - Not in allowed list (unknown/unapproved): 0. Additional calls from
          such a server never increase trust.
        - In allowed list but not registered with capabilities: 30, reduced by
          observed call volume down to a floor (unproven server accumulating
          traffic is more suspicious, not less).
        - Registered with declared capabilities during the approved/init phase:
          high base trust (90). Slightly reduced if it starts exhibiting
          anomalously high call volume, but never below a trusted floor.
        """
        # Unknown / unapproved server: no trust, regardless of call volume.
        if server_id not in self._allowed:
            return 0

        info = self._registry.get(server_id)
        call_count = info["call_count"] if info else self._unregistered_calls.get(server_id, 0)

        if info is None:
            # Allowed but never went through capability registration. Treat as
            # provisional: start at 30 and DECREASE as unproven call volume
            # grows, because an unproven endpoint driving lots of traffic is a
            # risk signal, not a trust signal. Floor at 10.
            penalty = min(call_count * 5, 20)
            return max(30 - penalty, 10)

        # Server was known/approved during initialization and declared its
        # capabilities: it earns high base trust from provenance.
        base = 90
        # A registered server showing abnormally high volume gets a small
        # penalty (possible compromise / abuse), but stays within a trusted
        # band. Never let volume push trust UP.
        volume_penalty = min(max(call_count - 20, 0), 20)
        return max(min(base - volume_penalty, 100), 70)

    @property
    def allowed_servers(self) -> set[str]:
        """Return current set of allowed server IDs."""
        return set(self._allowed)

    @property
    def registered_servers(self) -> dict[str, dict[str, Any]]:
        """Return registry info (read-only copy)."""
        return dict(self._registry)
