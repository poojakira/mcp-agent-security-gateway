"""Policy-as-code decision layer for MCP tool calls.

This package provides a fail-closed Policy Decision Point (PDP) implemented in
pure Python (``policy_engine``). The same authorization logic is also expressed
as Rego policies under ``policy/rego/`` at the repo root so it can be verified
with ``opa test`` on a machine that has the OPA binary installed.

The Python PDP is the VERIFIABLE path in this repository (covered by pytest).
The Rego path is provided for parity/portability but is UNVERIFIED here because
the OPA binary is not installed in this environment.
"""

from mcp_monitor.policy.policy_engine import (
    PolicyDecision,
    PolicyEngine,
    PolicyInput,
    ReasonCode,
)

__all__ = [
    "PolicyEngine",
    "PolicyDecision",
    "PolicyInput",
    "ReasonCode",
]
