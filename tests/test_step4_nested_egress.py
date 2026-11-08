"""Step 4 bounded recursive egress validation with controlled JSON fixtures."""

from __future__ import annotations

import pytest

from mcp_monitor.policy.policy_engine import PolicyEngine, ReasonCode


@pytest.fixture
def engine() -> PolicyEngine:
    return PolicyEngine(
        allowed_servers={"synthetic"},
        allowed_egress_hosts={"approved.example"},
    )


@pytest.mark.parametrize(
    "arguments",
    [
        {"operation": {"destination": "https://unapproved.example/private"}},
        {"operation": [{"url": "https://unapproved.example/private"}]},
        {"url": "https://approved.example", "options": {"host": "unapproved.example"}},
        {"tasks": [{"metadata": {"ENDPOINT": "http://127.0.0.1/admin"}}]},
        {"params": {"Destination": "https://unapproved.example"}},
        {"nested": {"target": "https://unapproved.example"}},
    ],
)
def test_nested_destinations_deny_unauthorized_host(
    engine: PolicyEngine, arguments: dict
) -> None:
    decision = engine.evaluate(
        {"name": "http_get", "server_id": "synthetic", "arguments": arguments}
    )
    assert not decision.allowed
    assert decision.reason_code == ReasonCode.DENY_EGRESS_NOT_ALLOWED


@pytest.mark.parametrize(
    "argument",
    [
        {"options": {"url": 12}},
        {"tasks": [{"destination": []}]},
        {"operation": {"endpoint": ""}},
        {"options": {"host": False}},
    ],
)
def test_nested_malformed_destinations_fail_closed(
    engine: PolicyEngine, argument: dict
) -> None:
    decision = engine.evaluate(
        {"name": "http_get", "server_id": "synthetic", "arguments": argument}
    )
    assert not decision.allowed
    assert decision.reason_code == ReasonCode.DENY_EGRESS_MALFORMED


def test_multiple_nested_approved_hosts_allowed(engine: PolicyEngine) -> None:
    decision = engine.evaluate(
        {
            "name": "http_get",
            "server_id": "synthetic",
            "arguments": {
                "requests": [
                    {"url": "https://approved.example/a"},
                    {"options": {"destination": "approved.example"}},
                ]
            },
        }
    )
    assert decision.allowed


def test_excessive_nesting_denied_not_crashed(engine: PolicyEngine) -> None:
    root: dict = {}
    cursor = root
    for _ in range(20):
        nested: dict = {}
        cursor["child"] = nested
        cursor = nested
    decision = engine.evaluate(
        {"name": "http_get", "server_id": "synthetic", "arguments": root}
    )
    assert not decision.allowed
    assert decision.reason_code == ReasonCode.DENY_EGRESS_MALFORMED


def test_excessive_elements_denied_not_crashed(engine: PolicyEngine) -> None:
    decision = engine.evaluate(
        {
            "name": "http_get",
            "server_id": "synthetic",
            "arguments": {"items": [{"note": "synthetic"} for _ in range(4100)]},
        }
    )
    assert not decision.allowed
    assert decision.reason_code == ReasonCode.DENY_EGRESS_MALFORMED


def test_unrecognized_nested_free_text_is_not_network_enforcement(
    engine: PolicyEngine,
) -> None:
    decision = engine.evaluate(
        {
            "name": "text_reader",
            "server_id": "synthetic",
            "arguments": {
                "user_text": "See https://unapproved.example for documentation"
            },
        }
    )
    assert decision.allowed
