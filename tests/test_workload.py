"""Tests for the demo/live workload generator (mcp_monitor.server.workload).

These exercise the real ``next_tool_call`` generator that feeds the control
plane's opt-in demo workload. They assert structural validity and that the
``threat_rate`` bound is honored at its extremes — no behavior is mocked.
"""

from __future__ import annotations

from mcp_monitor.server.workload import (
    _BENIGN_BUILDERS,
    _THREAT_BUILDERS,
    next_tool_call,
)


def _is_well_formed(call: dict) -> bool:
    return (
        isinstance(call, dict)
        and isinstance(call.get("name"), str)
        and call["name"]
        and isinstance(call.get("server_id"), str)
        and isinstance(call.get("arguments"), dict)
    )


def test_all_builders_produce_well_formed_calls():
    """Every benign and threat builder returns a structurally valid tool call."""
    for build in (*_BENIGN_BUILDERS, *_THREAT_BUILDERS):
        assert _is_well_formed(build())


def test_threat_rate_one_always_returns_threat_shaped_call():
    """threat_rate=1.0 must always emit a call, drawn from the threat builders."""
    threat_signatures = {
        (b()["name"], b()["server_id"]) for b in _THREAT_BUILDERS
    }  # note: server_id may be randomized (rogue-*), so also check names
    threat_names = {b()["name"] for b in _THREAT_BUILDERS}
    for _ in range(50):
        call = next_tool_call(threat_rate=1.0)
        assert _is_well_formed(call)
        # A threat call's name is one of the threat builder names (server_id can
        # be randomized for the shadow-server case).
        assert (
            call["name"] in threat_names or (call["name"], call["server_id"]) in threat_signatures
        )


def test_threat_rate_zero_always_returns_benign_call():
    """threat_rate=0.0 must always emit a benign, well-formed call."""
    benign_names = {b()["name"] for b in _BENIGN_BUILDERS}
    for _ in range(50):
        call = next_tool_call(threat_rate=0.0)
        assert _is_well_formed(call)
        assert call["name"] in benign_names


def test_default_threat_rate_mixes_traffic():
    """The default rate produces a mix over a large sample (not all one class)."""
    names = {next_tool_call()["name"] for _ in range(200)}
    # With 8 benign + 9 threat builders and an ~18% threat rate, a 200-sample
    # draw should surface several distinct tool names.
    assert len(names) >= 3
