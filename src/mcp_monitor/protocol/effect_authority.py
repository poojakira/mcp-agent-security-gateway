"""Trusted, in-process permits for explicitly approved MCP side effects.

This keyless laboratory authority binds an opaque operation identifier to the
trusted operator's principal, server, tool and canonical arguments. Identifiers
are NOT credentials and a client-supplied identifier does not grant authority.
The operator must control the authority instance and process isolation. This
does not prove a real-world user consented or that an external effect occurred.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from types import MappingProxyType

from mcp_monitor.protocol.effect_journal import EffectJournalError, _fingerprint, _label


@dataclass(frozen=True, slots=True)
class EffectPermit:
    """One operator-provisioned, exact-argument effect approval."""

    principal: str
    server: str
    tool: str
    operation_key: str
    argument_hash: str

    @classmethod
    def for_arguments(
        cls,
        *,
        principal: str,
        server: str,
        tool: str,
        operation_key: str,
        arguments: object,
    ) -> EffectPermit:
        return cls(
            principal=_label(principal, "principal"),
            server=_label(server, "server"),
            tool=_label(tool, "tool"),
            operation_key=_label(operation_key, "operation key"),
            argument_hash=_fingerprint(arguments),
        )


class TrustedEffectAuthority:
    """Immutable set of trusted, exact-operation permits provisioned by operator."""

    def __init__(self, permits: list[EffectPermit] | tuple[EffectPermit, ...]) -> None:
        if not isinstance(permits, list | tuple) or not permits:
            raise ValueError("At least one trusted effect permit is required")
        approved: dict[tuple[str, str, str, str], str] = {}
        for permit in permits:
            if not isinstance(permit, EffectPermit):
                raise ValueError("Invalid trusted effect permit")
            key = (
                _label(permit.principal, "principal"),
                _label(permit.server, "server"),
                _label(permit.tool, "tool"),
                _label(permit.operation_key, "operation key"),
            )
            if (
                len(permit.argument_hash) != 64
                or any(char not in "0123456789abcdef" for char in permit.argument_hash)
                or key in approved
            ):
                raise ValueError("Malformed or duplicated trusted effect permit")
            approved[key] = permit.argument_hash
        # The trusted operator may replace the authority instance, but an MCP
        # client cannot mutate permitted operations through request arguments.
        self._approved = MappingProxyType(approved)

    def authorize(
        self,
        *,
        principal: str,
        server: str,
        tool: str,
        operation_key: str,
        arguments: object,
    ) -> None:
        key = (
            _label(principal, "principal"),
            _label(server, "server"),
            _label(tool, "tool"),
            _label(operation_key, "operation key"),
        )
        digest = _fingerprint(arguments)
        expected = self._approved.get(key)
        if expected is None or not hmac.compare_digest(expected, digest):
            raise EffectJournalError("Side effect lacks an exact trusted operator approval")
