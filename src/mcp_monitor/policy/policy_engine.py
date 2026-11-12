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
    DENY_TOOL_NOT_ALLOWED = "DENY_TOOL_NOT_ALLOWED"
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
        allowed_tools: set[str] | frozenset[str] | None = None,
    ) -> None:
        # Copy into frozen sets so config cannot be mutated after construction.
        if allowed_tools is not None and (
            not isinstance(allowed_tools, set | frozenset)
            or any(not isinstance(name, str) or not name for name in allowed_tools)
        ):
            raise ValueError("allowed_tools must be a trusted set of nonempty tool names")
        self.allowed_tools: frozenset[str] | None = (
            frozenset(allowed_tools) if allowed_tools is not None else None
        )
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

        # Explicit tool capabilities are required by the hardened CLI. Library
        # callers must opt in to this control until the legacy API is migrated.
        if self.allowed_tools is not None and pi.tool_name not in self.allowed_tools:
            return PolicyDecision(
                allowed=False,
                reason_code=ReasonCode.DENY_TOOL_NOT_ALLOWED,
                message="Tool is not in the trusted capability allowlist",
                matched_rule="tool_authorization.tool_allowlist",
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

    def _extract_destinations(self, pi: PolicyInput) -> list[Any]:
        """Inspect recognized destinations throughout bounded JSON arguments.

        Only destination-shaped keys are interpreted as URLs or hosts.
        Arbitrary free-form text and opaque tool schemas remain out of scope.
        """
        if not isinstance(pi.arguments, dict):
            raise ValueError("Invalid egress argument object")
        destinations: list[Any] = []
        if pi.egress_destination is not None:
            destinations.append(pi.egress_destination)

        keys = frozenset({"url", "host", "endpoint", "target", "destination"})
        pending: list[tuple[Any, int]] = [(pi.arguments, 0)]
        nodes = 0
        while pending:
            node, depth = pending.pop()
            nodes += 1
            if nodes > 4096 or depth > 16:
                raise ValueError("Egress argument inspection limit exceeded")
            if isinstance(node, dict):
                if len(node) + len(pending) > 4096:
                    raise ValueError("Egress argument inspection limit exceeded")
                for key, value in node.items():
                    if not isinstance(key, str):
                        raise ValueError("Invalid egress argument key")
                    if key.lower() in keys and value is not None:
                        destinations.append(value)
                    pending.append((value, depth + 1))
            elif isinstance(node, list):
                if len(node) + len(pending) > 4096:
                    raise ValueError("Egress argument inspection limit exceeded")
                pending.extend((value, depth + 1) for value in node)
        return destinations

    @staticmethod
    def _host_from_destination(dest: str) -> str | None:
        """Extract a host only from a well-formed HTTP(S) URL or bare host.

        This is argument validation, NOT socket egress enforcement. A real
        egress proxy must still constrain DNS, resolved IP, port, redirects
        and all downstream network paths.
        """
        dest = dest.strip()
        if not dest or any(ord(char) <= 32 or ord(char) == 127 for char in dest):
            return None
        # Reject userinfo, non-HTTP schemes, malformed ports and ambiguous
        # authority separators rather than approving by hostname alone.
        if "://" in dest:
            try:
                parsed = urlparse(dest)
                if parsed.scheme.lower() not in {"http", "https"}:
                    return None
                if not parsed.netloc or parsed.username is not None or parsed.password is not None:
                    return None
                if "\\" in parsed.netloc:
                    return None
                port = parsed.port
                host = parsed.hostname
                if port is not None and not 1 <= port <= 65535:
                    return None
                if not host or "%" in host:
                    return None
                return host
            except ValueError:
                return None
        # Bare host[:port] must not carry a path, query, fragment or
        # credentials. Bracketed IPv6 is treated separately.
        if any(char in dest for char in ("/", "?", "#", "@", "\\")):
            return None
        if dest.startswith("["):
            end = dest.find("]")
            if end == -1:
                return None
            host = dest[1:end]
            try:
                if ipaddress.ip_address(host).version != 6:
                    return None
            except ValueError:
                return None
            suffix = dest[end + 1 :]
            if suffix:
                if not suffix.startswith(":") or not suffix[1:].isdecimal():
                    return None
                if not 1 <= int(suffix[1:]) <= 65535:
                    return None
            return host
        if dest.count(":") == 1:
            host, port = dest.rsplit(":", 1)
            if not host or not port.isdecimal() or not 1 <= int(port) <= 65535:
                return None
            return host
        if ":" in dest:
            # Unbracketed IPv6 is accepted only when it is a valid literal.
            try:
                if ipaddress.ip_address(dest).version == 6:
                    return dest
            except ValueError:
                pass
            return None
        return dest if "%" not in dest else None

    def _evaluate_egress(self, pi: PolicyInput) -> PolicyDecision | None:
        """Deny if any declared egress destination is malformed or disallowed.

        Tool arguments are not authoritative egress metadata. This inspects
        only recognized fields; OS/network policies must restrict real sockets.
        """
        try:
            destinations = self._extract_destinations(pi)
        except (TypeError, ValueError):
            return PolicyDecision(
                allowed=False,
                reason_code=ReasonCode.DENY_EGRESS_MALFORMED,
                message="Unable to inspect egress arguments safely",
                matched_rule="egress.malformed",
            )
        for dest in destinations:
            if not isinstance(dest, str):
                return PolicyDecision(
                    allowed=False,
                    reason_code=ReasonCode.DENY_EGRESS_MALFORMED,
                    message="Invalid egress destination type",
                    matched_rule="egress.malformed",
                )
            try:
                host = self._host_from_destination(dest)
            except ValueError:
                host = None
            if host is None:
                return PolicyDecision(
                    allowed=False,
                    reason_code=ReasonCode.DENY_EGRESS_MALFORMED,
                    message="Could not parse egress destination, denied fail-closed",
                    matched_rule="egress.malformed",
                )

            host = host.lower()
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
