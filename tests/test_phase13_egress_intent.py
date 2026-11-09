"""Phase 13 egress-intent integrity checks; no network connections or API keys."""

from mcp_monitor.defense10.egress_proxy import EgressInspector, IntentRegistry


def test_missing_intent_fails_closed_even_for_empty_outbound_payload() -> None:
    inspector = EgressInspector(IntentRegistry())
    result = inspector.inspect("not-registered", {"safe": "no email address"})
    assert not result.allowed
    assert "No trusted" in result.reason


def test_expired_intent_fails_closed() -> None:
    registry = IntentRegistry(max_age_seconds=0.01)
    registry.record("operation", {"name": "send_email", "arguments": {"to": "safe@example.org"}})
    # Emulate passage of time without sleeping or network traffic.
    registry._intents["operation"]["ts"] -= 3600
    result = EgressInspector(registry).inspect("operation", {"To": "safe@example.org"})
    assert not result.allowed


def test_matching_registered_intent_allows_payload_in_scoped_heuristic() -> None:
    registry = IntentRegistry()
    registry.record("operation", {"name": "send_email", "arguments": {"to": "safe@example.org"}})
    result = EgressInspector(registry).inspect("operation", {"To": "safe@example.org"})
    assert result.allowed
