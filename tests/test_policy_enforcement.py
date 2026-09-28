"""Enforcement proof for the fail-closed Policy Decision Point (PDP).

These tests demonstrate ENFORCEMENT, not just decision-making: a tool call that
the PDP denies must NEVER reach the downstream MCP transport. We assert this by
wiring the PDP in front of a fake transport whose ``send``/``receive`` are
tracking mocks, and verifying they are not called on deny and are called on
allow.

The Python PDP is the verified path (see docs/policy/POLICY_AS_CODE.md).
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from mcp_monitor.policy.policy_engine import (
    PolicyDecision,
    PolicyEngine,
    PolicyInput,
    ReasonCode,
)


class FakeDownstreamTransport:
    """Stand-in for the downstream MCP server transport.

    ``send`` and ``receive`` are MagicMocks so tests can assert whether the
    gateway ever forwarded a call downstream.
    """

    def __init__(self) -> None:
        self.send = MagicMock(name="downstream.send")
        self.receive = MagicMock(name="downstream.receive", return_value={"result": "ok"})


class EnforcingGateway:
    """Minimal PEP (Policy Enforcement Point) that gates a downstream transport.

    This is the wiring under test: the PDP decides, and ONLY on allow does the
    request get forwarded to the downstream transport.
    """

    def __init__(self, engine: PolicyEngine, downstream: FakeDownstreamTransport) -> None:
        self.engine = engine
        self.downstream = downstream

    def handle(self, tool_call: dict[str, Any]) -> dict[str, Any]:
        decision: PolicyDecision = self.engine.evaluate(tool_call)
        if not decision.allowed:
            # Fail-closed: do NOT touch the downstream transport.
            return {
                "forwarded": False,
                "decision": decision.to_dict(),
            }
        # Allowed: forward downstream.
        self.downstream.send(tool_call)
        result = self.downstream.receive()
        return {
            "forwarded": True,
            "decision": decision.to_dict(),
            "result": result,
        }


@pytest.fixture
def engine() -> PolicyEngine:
    return PolicyEngine(
        allowed_servers={"filesystem", "search", "calculator"},
        allowed_egress_hosts={"api.example.com"},
    )


@pytest.fixture
def downstream() -> FakeDownstreamTransport:
    return FakeDownstreamTransport()


@pytest.fixture
def gateway(engine: PolicyEngine, downstream: FakeDownstreamTransport) -> EnforcingGateway:
    return EnforcingGateway(engine, downstream)


# ---------------------------------------------------------------------------
# Enforcement: DENY must not reach downstream
# ---------------------------------------------------------------------------


def test_dangerous_tool_denied_never_reaches_downstream(gateway, downstream):
    result = gateway.handle({"name": "shell_exec", "server_id": "search", "arguments": {}})
    assert result["forwarded"] is False
    assert result["decision"]["reason_code"] == ReasonCode.DENY_DANGEROUS_TOOL.value
    downstream.send.assert_not_called()
    downstream.receive.assert_not_called()


def test_disallowed_server_denied_never_reaches_downstream(gateway, downstream):
    result = gateway.handle({"name": "search_web", "server_id": "rogue", "arguments": {}})
    assert result["forwarded"] is False
    assert result["decision"]["reason_code"] == ReasonCode.DENY_SERVER_NOT_ALLOWED.value
    downstream.send.assert_not_called()
    downstream.receive.assert_not_called()


def test_disallowed_egress_denied_never_reaches_downstream(gateway, downstream):
    result = gateway.handle(
        {
            "name": "http_get",
            "server_id": "search",
            "arguments": {"url": "https://evil.attacker.net/steal"},
        }
    )
    assert result["forwarded"] is False
    assert result["decision"]["reason_code"] == ReasonCode.DENY_EGRESS_NOT_ALLOWED.value
    downstream.send.assert_not_called()
    downstream.receive.assert_not_called()


def test_loopback_egress_denied_never_reaches_downstream(gateway, downstream):
    result = gateway.handle(
        {
            "name": "http_get",
            "server_id": "search",
            "arguments": {"url": "http://127.0.0.1:8080/admin"},
        }
    )
    assert result["forwarded"] is False
    assert result["decision"]["reason_code"] == ReasonCode.DENY_EGRESS_NOT_ALLOWED.value
    downstream.send.assert_not_called()
    downstream.receive.assert_not_called()


def test_malformed_input_denied_never_reaches_downstream(gateway, downstream):
    # Missing server_id -> malformed -> fail closed.
    result = gateway.handle({"name": "search_web"})
    assert result["forwarded"] is False
    assert result["decision"]["reason_code"] == ReasonCode.DENY_MALFORMED_INPUT.value
    downstream.send.assert_not_called()
    downstream.receive.assert_not_called()


# ---------------------------------------------------------------------------
# Enforcement: ALLOW must reach downstream exactly once
# ---------------------------------------------------------------------------


def test_allowed_call_reaches_downstream(gateway, downstream):
    tool_call = {"name": "search_web", "server_id": "search", "arguments": {}}
    result = gateway.handle(tool_call)
    assert result["forwarded"] is True
    assert result["decision"]["reason_code"] == ReasonCode.ALLOWED.value
    downstream.send.assert_called_once_with(tool_call)
    downstream.receive.assert_called_once()
    assert result["result"] == {"result": "ok"}


def test_allowed_call_with_allowlisted_egress_reaches_downstream(gateway, downstream):
    tool_call = {
        "name": "http_get",
        "server_id": "search",
        "arguments": {"url": "https://api.example.com/data"},
    }
    result = gateway.handle(tool_call)
    assert result["forwarded"] is True
    downstream.send.assert_called_once()
    downstream.receive.assert_called_once()


# ---------------------------------------------------------------------------
# PDP unit behaviour: default-deny, deny-wins, fail-closed, structured output
# ---------------------------------------------------------------------------


def test_default_deny_for_unknown_server(engine):
    decision = engine.evaluate({"name": "x", "server_id": "unknown", "arguments": {}})
    assert decision.allowed is False
    assert decision.reason_code is ReasonCode.DENY_SERVER_NOT_ALLOWED


def test_deny_wins_dangerous_tool_beats_allowed_server(engine):
    # delete_file is dangerous AND server is allowed; deny must win.
    decision = engine.evaluate({"name": "delete_file", "server_id": "filesystem", "arguments": {}})
    assert decision.allowed is False
    assert decision.reason_code is ReasonCode.DENY_DANGEROUS_TOOL


def test_fail_closed_on_non_dict_input(engine):
    decision = engine.evaluate("not-a-dict")  # type: ignore[arg-type]
    assert decision.allowed is False
    assert decision.reason_code is ReasonCode.DENY_MALFORMED_INPUT


def test_decision_is_structured(engine):
    decision = engine.evaluate({"name": "add", "server_id": "calculator", "arguments": {}})
    d = decision.to_dict()
    assert set(d.keys()) == {"allowed", "reason_code", "message", "matched_rule"}
    assert d["allowed"] is True
    assert d["reason_code"] == ReasonCode.ALLOWED.value


def test_policy_input_accepted_directly(engine):
    pi = PolicyInput(tool_name="add", server_id="calculator", arguments={})
    decision = engine.evaluate(pi)
    assert decision.allowed is True


def test_bare_host_egress_allowlisted(engine):
    decision = engine.evaluate(
        {"name": "http_get", "server_id": "search", "arguments": {"host": "api.example.com:443"}}
    )
    assert decision.allowed is True


def test_bare_host_egress_denied(engine):
    decision = engine.evaluate(
        {"name": "http_get", "server_id": "search", "arguments": {"host": "bad.host.net"}}
    )
    assert decision.allowed is False
    assert decision.reason_code is ReasonCode.DENY_EGRESS_NOT_ALLOWED


def test_malformed_egress_destination_denied(engine):
    decision = engine.evaluate(
        {"name": "http_get", "server_id": "search", "arguments": {"url": "://"}}
    )
    assert decision.allowed is False
    assert decision.reason_code in (
        ReasonCode.DENY_EGRESS_MALFORMED,
        ReasonCode.DENY_EGRESS_NOT_ALLOWED,
    )
