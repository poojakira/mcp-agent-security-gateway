"""Synthetic Week 1 wiring tests; these are NOT the nine frozen events."""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from mcp_monitor.experiments.ontology_pilot import (
    Event,
    GateDecision,
    GatewaySkeleton,
    HarnessSkeleton,
    Lane,
    ModelRequest,
    PromptSet,
    Proposal,
)
from mcp_monitor.policy.policy_engine import PolicyEngine


@dataclass
class FakeModel:
    action: Proposal
    seen: list[ModelRequest] = field(default_factory=list)

    def propose(self, request: ModelRequest) -> Proposal:
        self.seen.append(request)
        return self.action


@dataclass
class FakeRules:
    ingress: bool = True
    tool: bool = True
    fail: bool = False

    def evaluate(self, stage: str, event: Event, proposal: Proposal | None) -> GateDecision:
        if self.fail:
            raise RuntimeError("synthetic rules outage")
        allowed = self.ingress if stage == "ingress" else self.tool
        return GateDecision(allowed, f"test_only.{stage}", "synthetic rules only")


@pytest.fixture
def event() -> Event:
    return Event("synthetic-1", "Synthetic request", "test-actor", "test-authority")


@pytest.fixture
def policy() -> PolicyEngine:
    return PolicyEngine(
        allowed_servers={"ontology-stub"},
        allowed_tools={"mock_read", "mock_set"},
        allowed_egress_hosts=set(),
    )


@pytest.fixture
def prompts() -> PromptSet:
    return PromptSet("test baseline prompt", "test governed prompt")


def test_d2_with_unfrozen_rules_blocks_before_model(event, policy, prompts):
    model = FakeModel(Proposal("mock_set", {"key": "x", "value": 1}, "try"))
    harness = HarnessSkeleton(model, GatewaySkeleton(policy), prompts)
    row = harness.run_one(event, Lane.ONTOLOGY_GATE)
    assert row.ingress_decision["rule_id"] == "rules_not_frozen"
    assert not row.model_called and not row.stub_executed
    assert row.state_before == row.state_after == {}
    assert model.seen == []


def test_ungoverned_has_no_authority_labels_or_gate(event, policy, prompts):
    model = FakeModel(Proposal("mock_set", {"key": "x", "value": 1}, "try"))
    harness = HarnessSkeleton(model, GatewaySkeleton(policy), prompts)
    row = harness.run_one(event, Lane.UNGOVERNED)
    assert row.stub_executed and row.state_after == {"x": 1}
    assert row.ingress_decision is None and row.tool_decision is None
    assert model.seen[0].actor_id is None
    assert model.seen[0].authority_basis is None
    assert model.seen[0].system_prompt == prompts.ungoverned


def test_d1_has_labels_but_no_gate(event, policy, prompts):
    model = FakeModel(Proposal("mock_read", {"key": "x"}, "inspect"))
    harness = HarnessSkeleton(model, GatewaySkeleton(policy), prompts)
    row = harness.run_one(event, Lane.ONTOLOGY)
    assert row.stub_executed
    assert row.tool_decision is None and row.ingress_decision is None
    assert model.seen[0].actor_id == "test-actor"
    assert model.seen[0].authority_basis == "test-authority"
    assert model.seen[0].system_prompt == prompts.governed


def test_d2_tool_denial_preserves_stub_state(event, policy, prompts):
    model = FakeModel(Proposal("mock_set", {"key": "x", "value": 1}, "try"))
    harness = HarnessSkeleton(model, GatewaySkeleton(policy, FakeRules(tool=False)), prompts)
    row = harness.run_one(event, Lane.ONTOLOGY_GATE)
    assert row.model_called and not row.stub_executed
    assert row.tool_decision["rule_id"] == "test_only.tool"
    assert row.proposal["rationale"] == "try"
    assert row.state_before == row.state_after == {}


def test_d2_allow_requires_both_rule_and_existing_pdp(event, policy, prompts):
    model = FakeModel(Proposal("mock_set", {"key": "x", "value": 1}, "try"))
    harness = HarnessSkeleton(model, GatewaySkeleton(policy, FakeRules()), prompts)
    row = harness.run_one(event, Lane.ONTOLOGY_GATE)
    assert row.stub_executed and row.state_after == {"x": 1}
    assert row.tool_decision["rule_id"] == "test_only.tool"
    assert row.proposal["tool_name"] == "mock_set"


def test_dangerous_tool_denied_even_by_permissive_fake_rules(event, policy, prompts):
    model = FakeModel(Proposal("delete_file", {}, "bad test"))
    harness = HarnessSkeleton(model, GatewaySkeleton(policy, FakeRules()), prompts)
    row = harness.run_one(event, Lane.ONTOLOGY_GATE)
    assert row.tool_decision["allowed"] is False
    assert not row.stub_executed
    assert row.state_before == row.state_after == {}


def test_ingress_failure_does_not_call_model(event, policy, prompts):
    model = FakeModel(Proposal("mock_set", {"key": "x", "value": 1}, "try"))
    harness = HarnessSkeleton(model, GatewaySkeleton(policy, FakeRules(fail=True)), prompts)
    row = harness.run_one(event, Lane.ONTOLOGY_GATE)
    assert row.ingress_decision["rule_id"] == "rule_error"
    assert model.seen == [] and not row.stub_executed


def test_tool_rule_failure_fails_closed(event, policy, prompts):
    @dataclass
    class ToolFailureRules:
        def evaluate(self, stage, event, proposal):
            if stage == "tool":
                raise RuntimeError("offline")
            return GateDecision(True, "test_only.ingress", "test")

    model = FakeModel(Proposal("mock_set", {"key": "x", "value": 1}, "try"))
    harness = HarnessSkeleton(model, GatewaySkeleton(policy, ToolFailureRules()), prompts)
    row = harness.run_one(event, Lane.ONTOLOGY_GATE)
    assert row.tool_decision["rule_id"] == "rule_error"
    assert not row.stub_executed


def test_d1_and_d2_share_exact_governed_prompt(event, policy, prompts):
    model = FakeModel(Proposal(None, {}, "no tool needed"))
    harness = HarnessSkeleton(model, GatewaySkeleton(policy, FakeRules()), prompts)
    harness.run_one(event, Lane.ONTOLOGY)
    harness.run_one(event, Lane.ONTOLOGY_GATE)
    assert model.seen[0] == model.seen[1]


def test_no_action_proposal_never_executes(event, policy, prompts):
    model = FakeModel(Proposal(None, {}, "decline"))
    harness = HarnessSkeleton(model, GatewaySkeleton(policy, FakeRules()), prompts)
    row = harness.run_one(event, Lane.ONTOLOGY_GATE)
    assert row.model_called and not row.stub_executed
    assert row.tool_decision is None


def test_unsupported_tool_has_no_side_effect(event, policy, prompts):
    model = FakeModel(Proposal("shell_exec", {}, "try"))
    harness = HarnessSkeleton(model, GatewaySkeleton(policy), prompts)
    row = harness.run_one(event, Lane.UNGOVERNED)
    assert not row.stub_executed
    assert row.error and "Unknown stub tool" in row.error
    assert row.state_before == row.state_after == {}


def test_invalid_event_is_rejected(policy, prompts):
    model = FakeModel(Proposal(None, {}, "no action"))
    harness = HarnessSkeleton(model, GatewaySkeleton(policy), prompts)
    with pytest.raises(ValueError, match="trusted"):
        harness.run_one(Event("", "text", "actor", "basis"), Lane.UNGOVERNED)


def test_unknown_lane_is_rejected(event, policy, prompts):
    model = FakeModel(Proposal(None, {}, "no action"))
    harness = HarnessSkeleton(model, GatewaySkeleton(policy), prompts)
    with pytest.raises(ValueError, match="Unknown lane"):
        harness.run_one(event, "d2")  # type: ignore[arg-type]


def test_missing_prompts_are_rejected(policy):
    model = FakeModel(Proposal(None, {}, "no action"))
    with pytest.raises(ValueError, match="frozen spec"):
        HarnessSkeleton(model, GatewaySkeleton(policy), PromptSet("", "test"))
