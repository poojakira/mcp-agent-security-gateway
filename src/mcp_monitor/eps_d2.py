"""EPS D2 external decision service. No model or harness imports; policy is supplied externally.

This module is an isolated experimental enforcement boundary, NOT a claim of Node1
deployment or of Eric's as-yet-unprovided canonical policy.
"""
from __future__ import annotations
import hashlib
import json
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

DECISIONS = frozenset({"ALLOW", "BLOCK", "ESCALATE"})
KINDS = frozenset({"instruction", "tool_call"})

def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)

@dataclass(frozen=True)
class Verdict:
    decision: str
    reason: str
    rule_id: str | None = None
    request_id: str | None = None
    def as_dict(self) -> dict[str, Any]:
        return {"decision": self.decision, "reason": self.reason,
                "rule_id": self.rule_id, "request_id": self.request_id,
                "result": "held for second approval" if self.decision == "ESCALATE" else None}

class StubQueue:
    """Durable local stub; intentionally has no notification or approval executor."""
    def __init__(self, path: str | Path):
        self.lock = threading.Lock()
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.execute("CREATE TABLE IF NOT EXISTS holds (request_id TEXT PRIMARY KEY, digest TEXT NOT NULL, payload TEXT NOT NULL, status TEXT NOT NULL CHECK(status='HELD'))")
        self.db.commit()
    def hold(self, request_id: str, payload: dict[str, Any]) -> None:
        serialized = canonical(payload)
        digest = hashlib.sha256(serialized.encode()).hexdigest()
        with self.lock:
            self.db.execute("INSERT INTO holds VALUES (?, ?, ?, 'HELD')", (request_id, digest, serialized))
            self.db.commit()
    def count(self) -> int:
        return self.db.execute("SELECT count(*) FROM holds").fetchone()[0]

class D2Gate:
    """Strict exact-match rule evaluator; default BLOCK, ambiguous matches BLOCK."""
    def __init__(self, policy: dict[str, Any], queue: StubQueue):
        self.queue = queue
        self.rules = []
        if not isinstance(policy, dict) or policy.get("schema_version") != 1 or not isinstance(policy.get("rules"), list):
            raise ValueError("invalid policy")
        for rule in policy["rules"]:
            if (not isinstance(rule, dict) or set(rule) != {"id", "match", "decision"}
                or not isinstance(rule["id"], str) or not rule["id"]
                or not isinstance(rule["match"], dict) or not rule["match"]
                or rule["decision"] not in DECISIONS):
                raise ValueError("invalid rule")
            self.rules.append(rule)
        if len({r["id"] for r in self.rules}) != len(self.rules):
            raise ValueError("duplicate rule IDs")
    def decide(self, request: Any) -> Verdict:
        if not isinstance(request, dict):
            return Verdict("BLOCK", "malformed")
        required = {"request_id", "kind", "actor", "act_type", "tool", "payload"}
        if (set(request) != required or any(not isinstance(request[k], str) or not request[k].strip()
            for k in ("request_id", "actor", "act_type", "tool"))
            or request.get("kind") not in KINDS or not isinstance(request.get("payload"), dict)):
            return Verdict("BLOCK", "malformed")
        try:
            canonical(request)
            matches = [r for r in self.rules if all(request.get(k) == v for k, v in r["match"].items())]
            if len(matches) != 1:
                return Verdict("BLOCK", "unmatched_or_ambiguous", request_id=request["request_id"])
            rule = matches[0]
            if rule["decision"] == "ESCALATE":
                self.queue.hold(request["request_id"], request)
            return Verdict(rule["decision"], "policy", rule["id"], request["request_id"])
        except (ValueError, TypeError, sqlite3.Error):
            return Verdict("BLOCK", "evaluation_or_queue_failure", request_id=request.get("request_id"))

    def deliver(self, request: Any, downstream: Callable[[dict[str, Any]], Any]) -> tuple[Verdict, Any]:
        """No downstream invocation except ALLOW; do not expose downstream to untrusted harness."""
        verdict = self.decide(request)
        if verdict.decision != "ALLOW":
            return verdict, None
        return verdict, downstream(request)
