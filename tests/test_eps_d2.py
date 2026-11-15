"""Tests of D2 mechanics only. Canonical events require Eric's frozen fixtures."""
import pytest
from mcp_monitor.eps_d2 import D2Gate, StubQueue

def req(**updates):
    data = dict(request_id="r1", kind="tool_call", actor="alice", act_type="read",
                tool="stub.read", payload={"key": "x"})
    data.update(updates)
    return data

@pytest.fixture
def gate(tmp_path):
    return D2Gate({"schema_version": 1, "rules": [
        {"id": "r_allow", "match": {"actor": "alice", "act_type": "read", "tool": "stub.read", "kind": "tool_call"}, "decision": "ALLOW"},
        {"id": "r_hold", "match": {"actor": "alice", "act_type": "write", "tool": "stub.write", "kind": "tool_call"}, "decision": "ESCALATE"},
    ]}, StubQueue(tmp_path / "holds.sqlite"))

def test_allow_executes_once(gate):
    calls = []
    verdict, result = gate.deliver(req(), lambda x: calls.append(x) or "ok")
    assert verdict.decision == "ALLOW" and result == "ok" and len(calls) == 1

def test_unmatched_never_executes(gate):
    calls = []
    verdict, result = gate.deliver(req(actor="unknown"), lambda x: calls.append(x))
    assert verdict.decision == "BLOCK" and result is None and not calls

@pytest.mark.parametrize("bad", [None, [], {}, {"request_id": "r1"}, req(kind="unknown"), req(payload=[]), req(extra=1)])
def test_malformed_blocks(gate, bad):
    calls = []
    verdict, _ = gate.deliver(bad, lambda x: calls.append(x))
    assert verdict.decision == "BLOCK" and not calls

def test_escalate_holds_without_side_effect(gate):
    calls = []
    verdict, result = gate.deliver(req(act_type="write", tool="stub.write"), lambda x: calls.append(x))
    assert verdict.decision == "ESCALATE" and verdict.as_dict()["result"] == "held for second approval"
    assert result is None and not calls and gate.queue.count() == 1

def test_queue_failure_blocks(tmp_path):
    q = StubQueue(tmp_path / "q.sqlite")
    q.db.close()
    gate = D2Gate({"schema_version": 1, "rules": [
        {"id": "hold", "match": {"act_type": "write"}, "decision": "ESCALATE"}]}, q)
    assert gate.decide(req(act_type="write")).decision == "BLOCK"

def test_ambiguous_policy_blocks(tmp_path):
    gate = D2Gate({"schema_version": 1, "rules": [
        {"id": "a", "match": {"actor": "alice"}, "decision": "ALLOW"},
        {"id": "b", "match": {"tool": "stub.read"}, "decision": "ALLOW"}]}, StubQueue(tmp_path / "q.sqlite"))
    assert gate.decide(req()).decision == "BLOCK"
