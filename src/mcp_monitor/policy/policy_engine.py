"""Fail-closed Policy Decision Point (PDP) for MCP tool calls.

This module evaluates authorization for MCP ``tools/call`` requests entirely in
Python. It mirrors the logic expressed in the Rego policies under
``policy/rego/`` so the two implementations stay in parity, but this Python PDP
is the path that is unit-tested and therefore VERIFIED in this repository.

Design principles
------------------
* **Default deny.** A request is denied unless a rule explicitly allows it and
  no rule denies it. Deny always wins over allow.
* **Fail closed.** Malformed input, unknown fields, or evaluation errors result
  in DENY, never ALLOW.
* **Structured decisions.** Every evaluation returns a :class:`PolicyDecision`
  with a machine-readable :class:`ReasonCode` and a human-readable message, so
  callers (and audit logs) get deterministic, explainable outcomes.

The three enforced controls (matching the Rego bundle):

1. ``tool_authorization`` -- deny dangerous/destructive tools outright and
   enforce a server allowlist.
2. ``egress`` -- block tool calls whose target network destination is not on
   the egress allowlist.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from urllib.parse import urlparse


class ReasonCode(str, Enum):
    """Machine-readable reason codes attached to every policy decision."""

    ALLOWED = "ALLOWED"
    DENY_DEFAULT = "DENY_DEFAULT"
    DENY_MALFORMED_INPUT = "DENY_MALFORMED_INPUT"
    DENY_DANGEROUS_TOOL = "DENY_DANGEROUS_TOOL"
    DENY_SERVER_NOT_ALLOWED = "DENY_SERVER_NOT_ALLOWED"
    DENY_EGRESS_NOT_ALLOWED = "DENY_EGRESS_NOT_ALLOWED"
    DENY_EGRESS_MALFORMED = "DENY_EGRESS_MALFORMED"


# Tools that are always denied regardless of server/egress. These represent
# destructive or privilege-escalating capabilities that an agent should never
# be able to invoke through the gateway.
DEFAULT_DANGEROUS_TOOLS: frozenset[str] = frozenset(
    {
        "shell_exec",
        "exec",
        "run_command",
        "delete_file",
        "rm",
        "drop_database",
        "write_iam_policy",
        "assume_role",
        "disable_logging",
        "modify_firewall",
    }
)


@dataclass(frozen=True)
class PolicyInput:
    """Normalized input to the PDP.

    Parameters
    ----------
    tool_name:
        The MCP tool being invoked (``tools/call`` ``name`` field).
    server_id:
        Identifier of the downstream MCP server that would handle the call.
    arguments:
        The tool-call arguments. May contain a ``url`` / ``host`` used for the
        egress check.
    egress_destination:
        Optional explicit network destination (host or URL). If not provided,
        the PDP attempts to derive it from ``arguments['url']`` /
        ``arguments['host']``.
    """

    tool_name: str
    server_id: str
    arguments: dict[str, Any] = field(default_factory=dict)
    egress_destination: str | None = None

    @classmethod
    def from_tool_call(cls, tool_call: dict[str, Any]) -> PolicyInput:
        """Build a :class:`PolicyInput` from a raw MCP tool-call dict.

        Raises
        ------
        ValueError
            If required fields are missing or of the wrong type. Callers should
            treat this as a fail-closed DENY.
        """
        if not isinstance(tool_call, dict):
            raise ValueError("tool_call must be a dict")
        name = tool_call.get("name")
        server_id = tool_call.get("server_id")
        arguments = tool_call.get("arguments", {})
        if not isinstance(name, str) or not name:
            raise ValueError("tool_call.name must be a non-empty string")
        if not isinstance(server_id, str) or not server_id:
            raise ValueError("tool_call.server_id must be a non-empty string")
        if not isinstance(arguments, dict):
            raise ValueError("tool_call.arguments must be a dict")
        return cls(
            tool_name=name,
            server_id=server_id,
            arguments=arguments,
            egress_destination=tool_call.get("egress_destination"),
        )


@dataclass(frozen=True)
class PolicyDecision:
    """Structured, explainable output of the PDP."""

    allowed: bool
    reason_code: ReasonCode
    message: str
    matched_rule: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason_code": self.reason_code.value,
            "message": self.message,
            "matched_rule": self.matched_rule,
        }


class PolicyEngine:
    """Fail-closed PDP evaluating MCP tool calls against policy-as-code rules.

    The engine is deterministic and side-effect free. ``evaluate`` never raises
    on bad input; instead it returns a DENY decision with an appropriate reason
    code (fail-closed).
    """

    def __init__(
        self,
        *,
        allowed_servers: set[str] | frozenset[str],
        allowed_egress_hosts: set[str] | frozenset[str] | None = None,
        dangerous_tools: set[str] | frozenset[str] | None = None,
    ) -> None:
        # Copy into frozen sets so config cannot be mutated after construction.
        self.allowed_servers: frozenset[str] = frozenset(allowed_servers)
        self.allowed_egress_hosts: frozenset[str] = frozenset(allowed_egress_hosts or set())
        self.dangerous_tools: frozenset[str] = (
            frozenset(dangerous_tools) if dangerous_tools is not None else DEFAULT_DANGEROUS_TOOLS
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(self, tool_call: dict[str, Any] | PolicyInput) -> PolicyDecision:
        """Evaluate a tool call. Default-deny, deny-wins, fail-closed.

        Accepts either a raw MCP tool-call dict or a pre-normalized
        :class:`PolicyInput`. Any normalization error yields a DENY.
        """
        # 1. Normalize / validate input (fail closed on malformed).
        try:
            pi = (
                tool_call
                if isinstance(tool_call, PolicyInput)
                else PolicyInput.from_tool_call(tool_call)
            )
        except Exception as exc:  # noqa: BLE001 - fail closed on any parse error
            return PolicyDecision(
                allowed=False,
                reason_code=ReasonCode.DENY_MALFORMED_INPUT,
                message=f"Malformed tool call, denied fail-closed: {exc}",
                matched_rule="input_validation",
            )

        # 2. Deny dangerous tools (deny wins, evaluated first).
        if pi.tool_name in self.dangerous_tools:
            return PolicyDecision(
                allowed=False,
                reason_code=ReasonCode.DENY_DANGEROUS_TOOL,
                message=f"Tool '{pi.tool_name}' is on the dangerous-tool denylist",
                matched_rule="tool_authorization.dangerous_tool",
            )

        # 3. Enforce server allowlist.
        if pi.server_id not in self.allowed_servers:
            return PolicyDecision(
                allowed=False,
                reason_code=ReasonCode.DENY_SERVER_NOT_ALLOWED,
                message=f"Server '{pi.server_id}' is not on the allowlist",
                matched_rule="tool_authorization.server_allowlist",
            )

        # 4. Egress check (only when a destination is present).
        egress_decision = self._evaluate_egress(pi)
        if egress_decision is not None:
            return egress_decision

        # 5. All checks passed -> explicit allow.
        return PolicyDecision(
            allowed=True,
            reason_code=ReasonCode.ALLOWED,
            message="Allowed: tool authorized, server on allowlist, egress permitted",
            matched_rule="allow",
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _extract_destination(self, pi: PolicyInput) -> str | None:
        """Return the raw egress destination string, or None if none present."""
        if pi.egress_destination:
            return pi.egress_destination
        args = pi.arguments
        for key in ("url", "host", "endpoint", "target"):
            val = args.get(key)
            if isinstance(val, str) and val:
                return val
        return None

    @staticmethod
    def _host_from_destination(dest: str) -> str | None:
        """Extract a hostname from a URL or bare host string.

        Returns None if the destination cannot be parsed into a host.
        """
        dest = dest.strip()
        if not dest:
            return None
        # If it looks like a URL, parse it.
        if "://" in dest:
            parsed = urlparse(dest)
            host = parsed.hostname
            return host or None
        # Bare host[:port] form.
        # Strip a trailing :port if present (but keep IPv6 literals intact).
        if dest.startswith("["):  # IPv6 literal e.g. [::1]:8080
            end = dest.find("]")
            if end != -1:
                return dest[1:end]
            return None
        if ":" in dest and dest.count(":") == 1:
            host = dest.split(":", 1)[0]
            return host or None
        return dest

    def _evaluate_egress(self, pi: PolicyInput) -> PolicyDecision | None:
        """Evaluate the egress allowlist.

        Returns a DENY decision if egress is disallowed/malformed, or ``None`` if
        there is nothing to enforce (no destination, or destination allowed).
        """
        dest = self._extract_destination(pi)
        if dest is None:
            # No network destination in this call -> egress control not applicable.
            return None

        host = self._host_from_destination(dest)
        if host is None:
            return PolicyDecision(
                allowed=False,
                reason_code=ReasonCode.DENY_EGRESS_MALFORMED,
                message=f"Could not parse egress destination '{dest}', denied fail-closed",
                matched_rule="egress.malformed",
            )

        host = host.lower()

        # Loopback / link-local are treated as disallowed egress unless explicitly
        # allowlisted, to avoid SSRF-style pivots.
        if self._is_blocked_ip(host) and host not in self.allowed_egress_hosts:
            return PolicyDecision(
                allowed=False,
                reason_code=ReasonCode.DENY_EGRESS_NOT_ALLOWED,
                message=f"Egress to internal/loopback address '{host}' is not allowed",
                matched_rule="egress.blocked_internal",
            )

        if host not in self.allowed_egress_hosts:
            return PolicyDecision(
                allowed=False,
                reason_code=ReasonCode.DENY_EGRESS_NOT_ALLOWED,
                message=f"Egress destination '{host}' is not on the allowlist",
                matched_rule="egress.allowlist",
            )

        return None

    @staticmethod
    def _is_blocked_ip(host: str) -> bool:
        """Return True if host is a loopback/link-local/private IP literal."""
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return False
        return ip.is_loopback or ip.is_link_local or ip.is_private
