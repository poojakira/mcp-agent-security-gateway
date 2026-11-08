"""Step 4 regression: malformed recognized egress fields must never be ignored."""

from __future__ import annotations

import pytest

from mcp_monitor.policy.policy_engine import PolicyEngine, ReasonCode


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("url", ""),
        ("host", ""),
        ("endpoint", 123),
        ("target", ["https://unapproved.example"]),
        ("url", {"nested": "https://unapproved.example"}),
        ("host", False),
    ],
)
def test_malformed_recognized_egress_fields_fail_closed(field: str, value: object) -> None:
    engine = PolicyEngine(
        allowed_servers={"synthetic"},
        allowed_egress_hosts={"approved.example"},
    )
    decision = engine.evaluate(
        {
            "name": "http_get",
            "server_id": "synthetic",
            "arguments": {"url": "https://approved.example", field: value},
        }
    )
    assert not decision.allowed
    assert decision.reason_code == ReasonCode.DENY_EGRESS_MALFORMED


def test_null_optional_egress_field_preserves_legacy_behavior() -> None:
    engine = PolicyEngine(
        allowed_servers={"synthetic"},
        allowed_egress_hosts={"approved.example"},
    )
    decision = engine.evaluate(
        {
            "name": "http_get",
            "server_id": "synthetic",
            "arguments": {"url": "https://approved.example", "endpoint": None},
        }
    )
    assert decision.allowed


def test_unrecognized_nested_destination_still_requires_network_enforcement() -> None:
    engine = PolicyEngine(allowed_servers={"synthetic"})
    decision = engine.evaluate(
        {
            "name": "indirect_request",
            "server_id": "synthetic",
            "arguments": {"operation": {"destination": "https://unapproved.example"}},
        }
    )
    # Documented residual risk: arbitrary nested tool schemas are not inspected.
    assert decision.allowed
