"""Tests for the SIEM attack-simulation scenario catalog.

These validate the statically-defined attack scenarios (no network calls) so the
detection/correlation catalog stays well-formed.
"""

from __future__ import annotations

import sys
from unittest.mock import patch

from mcp_monitor.siem import attack_simulations
from mcp_monitor.siem.attack_simulations import (
    ALL_SCENARIOS,
    AttackScenario,
    AttackStep,
    run_scenario,
)


def test_all_scenarios_present_and_well_formed():
    assert len(ALL_SCENARIOS) >= 3
    seen_ids = set()
    for scenario in ALL_SCENARIOS:
        assert isinstance(scenario, AttackScenario)
        assert scenario.scenario_id
        assert scenario.name
        assert scenario.description
        assert scenario.mitre_tactic
        # scenario ids must be unique
        assert scenario.scenario_id not in seen_ids
        seen_ids.add(scenario.scenario_id)
        # every scenario has at least one well-formed step
        assert scenario.steps
        for step in scenario.steps:
            assert isinstance(step, AttackStep)
            assert step.name
            assert step.expected_outcome in ("block", "allow")
            assert isinstance(step.tool_call, dict)


def test_scenario_steps_have_expected_outcomes():
    outcomes = {step.expected_outcome for scenario in ALL_SCENARIOS for step in scenario.steps}
    # The catalog should exercise both blocked and allowed outcomes.
    assert outcomes <= {"block", "allow"}
    assert "block" in outcomes


@patch.object(attack_simulations.time, "sleep", lambda *_: None)
def test_run_scenario_all_blocked(monkeypatch):
    """When the gateway blocks every step, matched steps are reported."""

    def fake_request(gateway_url, tool_call, session_id):
        return {"blocked": True, "findings": ["rule-x"]}

    monkeypatch.setattr(attack_simulations, "_make_request", fake_request)
    scenario = ALL_SCENARIOS[0]
    report = run_scenario(scenario, gateway_url="http://testhost", verbose=False)
    assert report["scenario_id"] == scenario.scenario_id
    assert len(report["results"]) == len(scenario.steps)


@patch.object(attack_simulations.time, "sleep", lambda *_: None)
def test_run_scenario_connection_error(monkeypatch):
    """Connection errors are surfaced without raising."""

    def fake_request(gateway_url, tool_call, session_id):
        return {"error": "refused", "status": 0}

    monkeypatch.setattr(attack_simulations, "_make_request", fake_request)
    report = run_scenario(ALL_SCENARIOS[0], verbose=False)
    assert report["results"]


def test_make_request_success(monkeypatch):
    """_make_request parses a JSON response body."""

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b'{"allowed": true}'

    monkeypatch.setattr(attack_simulations.urllib.request, "urlopen", lambda *a, **k: _Resp())
    out = attack_simulations._make_request("http://h", {"tool": "x"}, "sess")
    assert out == {"allowed": True}


def test_make_request_url_error(monkeypatch):
    """URLError is converted to an error dict with status 0."""

    def _raise(*a, **k):
        raise attack_simulations.urllib.error.URLError("boom")

    monkeypatch.setattr(attack_simulations.urllib.request, "urlopen", _raise)
    out = attack_simulations._make_request("http://h", {"tool": "x"}, "sess")
    assert out["status"] == 0


def test_main_list(monkeypatch, capsys):
    """`--list` prints the scenario catalog and returns without network calls."""
    monkeypatch.setattr(sys, "argv", ["attack_simulations", "--list"])
    attack_simulations.main()
    captured = capsys.readouterr()
    assert "Available Attack Scenarios" in captured.out
