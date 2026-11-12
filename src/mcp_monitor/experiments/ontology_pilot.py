"""Week 1 ontology pilot skeleton: simulated tool use only, no model endpoint.

This is an *interface scaffold*, not the v4 ontology, Eric's authority rules,
a six-cell runner, a completed ledger, or evidence of governance efficacy.
D2 fails closed until the external research rule hook is explicitly supplied.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Protocol

from mcp_monitor.policy.policy_engine import PolicyEngine


class Lane(str, Enum):
    UNGOVERNED = "ungoverned"
    ONTOLOGY = "d1"
    ONTOLOGY_GATE = "d2"


@dataclass(frozen=True)
class Event:
    event_id: str
    text: str
    actor_id: str
    authority_basis: str


@dataclass(frozen=True)
class PromptSet:
    ungoverned: str
    governed: str


@dataclass(frozen=True)
class ModelRequest:
    event_text: str
    system_prompt: str
    actor_id: str | None
    authority_basis: str | None


@dataclass(frozen=True)
class Proposal:
    tool_name: str | None
    arguments: dict[str, Any]
    rationale: str


class ModelPort(Protocol):
    def propose(self, request: ModelRequest) -> Proposal: ...


@dataclass(frozen=True)
class GateDecision:
    allowed: bool
    rule_id: str
    reason: str


class RulePort(Protocol):
    def evaluate(
        self, stage: str, event: Event, proposal: Proposal | None
    ) -> GateDecision: ...


class GatewaySkeleton:
    """Research-only bridge to the existing PDP; no invented L1/L2 rules."""

    def __init__(
        self, policy: PolicyEngine, rules: RulePort | None = None
    ) -> None:
        self._policy = policy
        self._rules = rules

    @staticmethod
    def _deny(rule_id: str, reason: str) -> GateDecision:
        return GateDecision(False, rule_id, reason)

    def check(
        self, stage: str, event: Event, proposal: Proposal | None = None
    ) -> GateDecision:
        if stage not in {"ingress", "tool"}:
            return self._deny("invalid_stage", "Unknown enforcement stage")
        if self._rules is None:
            return self._deny("rules_not_frozen", "Research L1/L2 rules not installed")
        if stage == "tool" and (
            not isinstance(proposal, Proposal)
            or not isinstance(proposal.tool_name, str)
            or not proposal.tool_name.strip()
            or not isinstance(proposal.arguments, dict)
        ):
            return self._deny("invalid_proposal", "Malformed tool proposal")
        try:
            verdict = self._rules.evaluate(stage, event, proposal)
            if not isinstance(verdict, GateDecision):
                return self._deny("invalid_rule_result", "Rule hook returned invalid decision")
            if not verdict.allowed:
                return verdict
            if not verdict.rule_id:
                return self._deny("missing_rule_id", "Allow lacks a governing rule")
            if stage == "tool":
                assert proposal is not None
                pdp = self._policy.evaluate(
                    {
                        "name": proposal.tool_name,
                        "server_id": "ontology-stub",
                        "arguments": proposal.arguments,
                    }
                )
                if not pdp.allowed:
                    return self._deny(pdp.matched_rule, pdp.reason_code.value)
            return verdict
        except Exception:
            return self._deny("rule_error", "Policy evaluation failed closed")


class InMemoryStubTools:
    """Fixed synthetic tools with no filesystem, network or subprocess access."""

    def __init__(self) -> None:
        self._state: dict[str, Any] = {}

    def snapshot(self) -> dict[str, Any]:
        return deepcopy(self._state)

    def execute(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        if name == "mock_read":
            key = args.get("key")
            if not isinstance(key, str) or not key:
                raise ValueError("mock_read requires a non-empty string key")
            return {"value": deepcopy(self._state.get(key))}
        if name == "mock_set":
            key = args.get("key")
            if not isinstance(key, str) or not key or "value" not in args:
                raise ValueError("mock_set requires key and value")
            self._state[key] = deepcopy(args["value"])
            return {"updated": key}
        raise ValueError("Unknown stub tool: no real tools are available")


@dataclass(frozen=True)
class RunRecord:
    event_id: str
    lane: str
    actor_id: str
    authority_basis: str
    model_called: bool
    proposal: dict[str, Any] | None
    ingress_decision: dict[str, Any] | None
    tool_decision: dict[str, Any] | None
    stub_executed: bool
    stub_result: dict[str, Any] | None
    state_before: dict[str, Any]
    state_after: dict[str, Any]
    error: str | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class HarnessSkeleton:
    """Single-event wiring; no runs or canonical experiment data bundled."""

    def __init__(
        self,
        model: ModelPort,
        gateway: GatewaySkeleton,
        prompts: PromptSet,
        tools: InMemoryStubTools | None = None,
    ) -> None:
        if not prompts.ungoverned or not prompts.governed:
            raise ValueError("Both prompts must be supplied from the frozen spec")
        self.model = model
        self.gateway = gateway
        self.prompts = prompts
        self.tools = tools if tools is not None else InMemoryStubTools()

    def run_one(self, event: Event, lane: Lane) -> RunRecord:
        if not isinstance(event, Event) or not all(
            isinstance(v, str) and v.strip()
            for v in (event.event_id, event.text, event.actor_id, event.authority_basis)
        ):
            raise ValueError("Event requires trusted, nonempty metadata and text")
        if not isinstance(lane, Lane):
            raise ValueError("Unknown lane")

        before = self.tools.snapshot()
        ingress: GateDecision | None = None
        tool: GateDecision | None = None
        proposal: Proposal | None = None
        called = False
        executed = False
        result: dict[str, Any] | None = None
        error: str | None = None

        if lane is Lane.ONTOLOGY_GATE:
            ingress = self.gateway.check("ingress", event)
        if ingress is None or ingress.allowed:
            request = ModelRequest(
                event_text=event.text,
                system_prompt=(
                    self.prompts.ungoverned
                    if lane is Lane.UNGOVERNED
                    else self.prompts.governed
                ),
                actor_id=None if lane is Lane.UNGOVERNED else event.actor_id,
                authority_basis=(
                    None if lane is Lane.UNGOVERNED else event.authority_basis
                ),
            )
            called = True
            try:
                proposal = self.model.propose(request)
                if not isinstance(proposal, Proposal):
                    raise ValueError("Model adapter must return a Proposal")
                if proposal.tool_name is not None and (
                    not isinstance(proposal.tool_name, str)
                    or not proposal.tool_name.strip()
                    or not isinstance(proposal.arguments, dict)
                ):
                    raise ValueError("Invalid proposed tool call")
                if proposal.tool_name is not None:
                    if lane is Lane.ONTOLOGY_GATE:
                        tool = self.gateway.check("tool", event, proposal)
                    if tool is None or tool.allowed:
                        result = self.tools.execute(
                            proposal.tool_name, proposal.arguments
                        )
                        executed = True
            except Exception as exc:
                error = f"{type(exc).__name__}: {exc}"
                # Model/transport errors do not grant authority to a tool.

        return RunRecord(
            event_id=event.event_id,
            lane=lane.value,
            actor_id=event.actor_id,
            authority_basis=event.authority_basis,
            model_called=called,
            proposal=asdict(proposal) if isinstance(proposal, Proposal) else None,
            ingress_decision=asdict(ingress) if ingress is not None else None,
            tool_decision=asdict(tool) if tool is not None else None,
            stub_executed=executed,
            stub_result=result,
            state_before=before,
            state_after=self.tools.snapshot(),
            error=error,
        )
