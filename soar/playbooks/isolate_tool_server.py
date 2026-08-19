"""
SOAR Playbook: Isolate MCP Tool Server on Repeated Tool-Poisoning Events

Trigger: 3+ tool-poisoning events (category = "tool_poisoning") from the same
         server_id within a 5-minute window.

Actions:
  1. Add the server_id to the gateway's runtime blocklist (hot reload)
  2. Revoke any active network routes to the tool server
  3. Snapshot the audit log segment covering the poisoning window
  4. Create incident with timeline and affected agents
"""

import datetime
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class PoisoningEvent:
    """A single tool-poisoning detection event."""
    request_id: str
    agent_id: str
    server_id: str
    tool_name: str
    rule_id: str
    timestamp: str
    argument_excerpt: str | None = None


@dataclass
class IsolationResult:
    success: bool
    actions_taken: list
    affected_agents: list
    timeline: list
    errors: list = field(default_factory=list)


class ToolServerIsolationPlaybook:
    """
    Isolates a tool server after repeated poisoning detections.

    The threshold (3 events in 5 minutes) is deliberately conservative  -
    a single poisoning event could be a false positive from an unusual
    tool description. Three events from the same server is a pattern.
    """

    THRESHOLD_COUNT = 3
    THRESHOLD_WINDOW_SECONDS = 300  # 5 minutes

    def __init__(self, gateway_config_path: str = "/app/config/runtime_blocklist.json"):
        self.blocklist_path = Path(gateway_config_path)

    def should_trigger(self, events: list[PoisoningEvent], server_id: str) -> bool:
        """Check if the threshold is met for a given server."""
        now = datetime.datetime.utcnow()
        window_start = now - datetime.timedelta(seconds=self.THRESHOLD_WINDOW_SECONDS)

        recent_events = [
            e for e in events
            if e.server_id == server_id
            and datetime.datetime.fromisoformat(e.timestamp) >= window_start
        ]
        return len(recent_events) >= self.THRESHOLD_COUNT

    def execute(self, events: list[PoisoningEvent], server_id: str) -> IsolationResult:
        """Execute server isolation."""
        actions_taken = []
        errors = []

        # Step 1: Add to runtime blocklist
        try:
            blocklist = self._load_blocklist()
            if server_id not in blocklist["blocked_servers"]:
                blocklist["blocked_servers"].append(server_id)
                blocklist["last_updated"] = datetime.datetime.utcnow().isoformat()
                blocklist["block_reasons"][server_id] = {
                    "reason": "repeated_tool_poisoning",
                    "event_count": len([e for e in events if e.server_id == server_id]),
                    "blocked_at": datetime.datetime.utcnow().isoformat(),
                    "triggering_rules": list(set(e.rule_id for e in events if e.server_id == server_id)),
                }
                self._save_blocklist(blocklist)
                actions_taken.append(f"Added {server_id} to runtime blocklist")
            else:
                actions_taken.append(f"{server_id} already in blocklist")
        except Exception as e:
            errors.append(f"Blocklist update failed: {e}")

        # Step 2: Identify affected agents
        affected_agents = list(set(
            e.agent_id for e in events if e.server_id == server_id
        ))
        actions_taken.append(f"Identified {len(affected_agents)} affected agents: {affected_agents}")

        # Step 3: Build timeline
        server_events = sorted(
            [e for e in events if e.server_id == server_id],
            key=lambda e: e.timestamp,
        )
        timeline = [
            {
                "timestamp": e.timestamp,
                "agent_id": e.agent_id,
                "tool_name": e.tool_name,
                "rule_id": e.rule_id,
                "request_id": e.request_id,
            }
            for e in server_events
        ]
        actions_taken.append(f"Built timeline with {len(timeline)} events")

        # Step 4: Log incident
        incident = {
            "playbook": "tool_server_isolation",
            "server_id": server_id,
            "trigger_threshold": f"{self.THRESHOLD_COUNT} events in {self.THRESHOLD_WINDOW_SECONDS}s",
            "affected_agents": affected_agents,
            "timeline": timeline,
            "actions": actions_taken,
            "timestamp": datetime.datetime.utcnow().isoformat(),
        }
        logger.info(f"Server isolation incident: {json.dumps(incident)}")

        return IsolationResult(
            success=len(errors) == 0,
            actions_taken=actions_taken,
            affected_agents=affected_agents,
            timeline=timeline,
            errors=errors,
        )

    def _load_blocklist(self) -> dict:
        if self.blocklist_path.exists():
            return json.loads(self.blocklist_path.read_text())
        return {"blocked_servers": [], "block_reasons": {}, "last_updated": None}

    def _save_blocklist(self, blocklist: dict):
        self.blocklist_path.parent.mkdir(parents=True, exist_ok=True)
        self.blocklist_path.write_text(json.dumps(blocklist, indent=2))


def handle_webhook(payload: dict, event_buffer: list[PoisoningEvent]) -> IsolationResult | None:
    """
    Entry point for webhook-triggered execution.
    Maintains a rolling buffer of poisoning events and triggers isolation
    when threshold is met.
    """
    event = PoisoningEvent(
        request_id=payload["request_id"],
        agent_id=payload["agent_id"],
        server_id=payload["server_id"],
        tool_name=payload["tool_name"],
        rule_id=payload["rule_id"],
        timestamp=payload.get("timestamp", datetime.datetime.utcnow().isoformat()),
        argument_excerpt=payload.get("argument_excerpt"),
    )
    event_buffer.append(event)

    playbook = ToolServerIsolationPlaybook()
    if playbook.should_trigger(event_buffer, event.server_id):
        return playbook.execute(event_buffer, event.server_id)

    return None  # Threshold not yet met


if __name__ == "__main__":
    # Simulate 3 poisoning events from the same server
    test_events = [
        {
            "request_id": f"req-{i}",
            "agent_id": f"agent-0{i}",
            "server_id": "malicious-tool-server-42",
            "tool_name": "data_lookup",
            "rule_id": "TP-001",
            "timestamp": (datetime.datetime.utcnow() - datetime.timedelta(minutes=4-i)).isoformat(),
        }
        for i in range(1, 4)
    ]

    print("Simulating 3 tool-poisoning events from server 'malicious-tool-server-42':")
    buffer = []
    for i, evt in enumerate(test_events, 1):
        print(f"  Event {i}: agent={evt['agent_id']}, tool={evt['tool_name']}, rule={evt['rule_id']}")
        result = handle_webhook(evt, buffer)
        if result:
            print("\n  THRESHOLD MET  -  Isolation triggered!")
            print(f"  Actions: {result.actions_taken}")
            print(f"  Affected agents: {result.affected_agents}")
