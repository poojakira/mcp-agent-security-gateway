"""Correlation engine for detecting multi-event attack patterns.

Maintains a sliding window of security events and evaluates them
against correlation rules that detect attack sequences spanning
multiple tool calls. A single blocked tool call may be noisy;
a sequence of reconnaissance + data access + exfiltration attempt
within a time window is a stronger signal.

Design decisions:
- In-memory sliding window (not persisted across restarts)
- Per-session correlation (events grouped by agent/session)
- Time-window based expiry (configurable, default 5 minutes)
- Rules are composable: each rule defines a sequence of conditions
"""

from __future__ import annotations

import time
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SecurityEvent:
    """Internal event representation for correlation."""

    timestamp: float
    event_type: str  # "block", "allow", "rate_limit", "circuit_breaker"
    tool_name: str = ""
    server_id: str = ""
    agent_id: str = ""
    session_id: str = ""
    enforcement_action: str = ""
    layer_name: str = ""
    risk_score: int = 0
    findings: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class CorrelationMatch:
    """Result of a correlation rule match."""

    rule_id: str
    rule_name: str
    severity: str  # critical, high, medium, low
    description: str
    matched_events: list[SecurityEvent]
    matched_at: float = field(default_factory=time.time)
    mitre_tactic: str = ""
    mitre_technique: str = ""


@dataclass
class CorrelationRule:
    """A rule that matches a sequence of events within a time window.

    Each condition is a callable that takes a SecurityEvent and returns
    True if that event satisfies that stage of the attack pattern.
    The rule fires when all conditions are satisfied (in order)
    within the specified time window for the same session.
    """

    rule_id: str
    name: str
    description: str
    severity: str  # critical, high, medium, low
    conditions: list[Callable[[SecurityEvent], bool]]
    window_seconds: float = 300.0  # 5 minutes default
    mitre_tactic: str = ""
    mitre_technique: str = ""
    min_events: int = 2  # minimum distinct events to trigger

    def evaluate(self, events: list[SecurityEvent]) -> CorrelationMatch | None:
        """Check if events satisfy all conditions within the time window.

        Events must satisfy conditions in order (though other events
        may appear between them).
        """
        if len(events) < self.min_events:
            return None

        # Find events matching each condition in sequence
        matched: list[SecurityEvent] = []
        condition_idx = 0

        for event in events:
            if condition_idx >= len(self.conditions):
                break
            if self.conditions[condition_idx](event):
                matched.append(event)
                condition_idx += 1

        # Check if all conditions were satisfied
        if condition_idx < len(self.conditions):
            return None

        # Check time window
        if matched:
            time_span = matched[-1].timestamp - matched[0].timestamp
            if time_span > self.window_seconds:
                return None

        return CorrelationMatch(
            rule_id=self.rule_id,
            rule_name=self.name,
            severity=self.severity,
            description=self.description,
            matched_events=matched,
            mitre_tactic=self.mitre_tactic,
            mitre_technique=self.mitre_technique,
        )


class CorrelationEngine:
    """Maintains event windows and evaluates correlation rules.

    Usage:
        engine = CorrelationEngine(window_seconds=300)
        engine.add_rules(BUILTIN_RULES)
        engine.ingest(event)
        matches = engine.evaluate()
    """

    def __init__(self, window_seconds: float = 300.0, max_events_per_session: int = 1000) -> None:
        self.window_seconds = window_seconds
        self.max_events_per_session = max_events_per_session
        self.rules: list[CorrelationRule] = []
        # Events grouped by session_id for correlation
        self._sessions: dict[str, list[SecurityEvent]] = defaultdict(list)
        self._global_events: list[SecurityEvent] = []

    def add_rule(self, rule: CorrelationRule) -> None:
        """Register a correlation rule."""
        self.rules.append(rule)

    def add_rules(self, rules: list[CorrelationRule]) -> None:
        """Register multiple correlation rules."""
        self.rules.extend(rules)

    def ingest(self, event: SecurityEvent) -> list[CorrelationMatch]:
        """Add an event and immediately evaluate rules.

        Returns any new correlation matches triggered by this event.
        """
        # Add to session window
        session_key = event.session_id or event.agent_id or "_global"
        self._sessions[session_key].append(event)
        self._global_events.append(event)

        # Expire old events
        self._expire_old_events(session_key)

        # Evaluate rules against this session
        return self._evaluate_session(session_key)

    def evaluate_all(self) -> list[CorrelationMatch]:
        """Evaluate all rules against all active sessions."""
        matches: list[CorrelationMatch] = []
        for session_key in list(self._sessions.keys()):
            self._expire_old_events(session_key)
            matches.extend(self._evaluate_session(session_key))
        return matches

    def get_session_events(self, session_id: str) -> list[SecurityEvent]:
        """Get current events for a session (for investigation)."""
        return list(self._sessions.get(session_id, []))

    def get_active_sessions(self) -> list[str]:
        """List sessions with active events."""
        return [k for k, v in self._sessions.items() if v]

    def get_stats(self) -> dict[str, Any]:
        """Return engine statistics."""
        return {
            "active_sessions": len(self._sessions),
            "total_events": sum(len(v) for v in self._sessions.values()),
            "rules_loaded": len(self.rules),
            "window_seconds": self.window_seconds,
        }

    def _expire_old_events(self, session_key: str) -> None:
        """Remove events older than the correlation window."""
        cutoff = time.time() - self.window_seconds
        self._sessions[session_key] = [
            e for e in self._sessions[session_key] if e.timestamp > cutoff
        ]
        # Cap per-session to prevent memory growth
        if len(self._sessions[session_key]) > self.max_events_per_session:
            self._sessions[session_key] = self._sessions[session_key][
                -self.max_events_per_session :
            ]
        # Remove empty sessions
        if not self._sessions[session_key]:
            del self._sessions[session_key]

    def _evaluate_session(self, session_key: str) -> list[CorrelationMatch]:
        """Evaluate all rules against a specific session's events."""
        events = self._sessions.get(session_key, [])
        if not events:
            return []

        matches: list[CorrelationMatch] = []
        for rule in self.rules:
            match = rule.evaluate(events)
            if match:
                matches.append(match)
        return matches


# ============================================================
# Built-in correlation rules for common agent attack patterns
# ============================================================


def _is_recon_event(event: SecurityEvent) -> bool:
    """Stage 1: Reconnaissance - listing tools, probing servers."""
    recon_indicators = ["tools/list", "list_tools", "discover", "enumerate"]
    return any(
        ind in event.tool_name.lower() or ind in " ".join(event.findings).lower()
        for ind in recon_indicators
    )


def _is_sensitive_access(event: SecurityEvent) -> bool:
    """Stage 2: Accessing sensitive data or resources."""
    sensitive_indicators = [
        "read_file",
        "get_secret",
        "database",
        "credentials",
        "pii",
        "sensitive",
        "password",
        "token",
        "key",
    ]
    return any(
        ind in event.tool_name.lower() or ind in " ".join(event.findings).lower()
        for ind in sensitive_indicators
    )


def _is_exfil_attempt(event: SecurityEvent) -> bool:
    """Stage 3: Exfiltration attempt."""
    return (
        event.layer_name == "network_egress"
        or "exfiltration" in " ".join(event.findings).lower()
        or "hidden_recipient" in " ".join(event.findings).lower()
        or event.enforcement_action in ("block", "deny")
        and any(
            f in " ".join(event.findings).lower()
            for f in ["bcc", "external", "raw_ip", "oversized"]
        )
    )


def _is_injection_attempt(event: SecurityEvent) -> bool:
    """Prompt injection detected in tool arguments."""
    return (
        "prompt_injection" in " ".join(event.findings).lower()
        or "injection" in event.layer_name.lower()
        or any("injection" in f.lower() for f in event.findings)
    )


def _is_privilege_escalation(event: SecurityEvent) -> bool:
    """Process spawn or privilege escalation indicators."""
    return event.layer_name == "process_spawn" or any(
        ind in " ".join(event.findings).lower()
        for ind in ["subprocess", "os.system", "cmd.exe", "bash", "shell"]
    )


def _is_server_trust_violation(event: SecurityEvent) -> bool:
    """Unregistered or unexpected MCP server."""
    return (
        event.layer_name == "server_trust"
        or "unregistered" in " ".join(event.findings).lower()
        or "shadow_server" in " ".join(event.findings).lower()
    )


def _is_blocked(event: SecurityEvent) -> bool:
    """Any blocked event."""
    return event.enforcement_action in ("block", "deny", "quarantine")


def _is_repeated_block(event: SecurityEvent) -> bool:
    """Blocked event with high risk score (persistent attacker)."""
    return event.enforcement_action in ("block", "deny") and event.risk_score >= 60


# Define the built-in rules

RECON_TO_EXFIL_RULE = CorrelationRule(
    rule_id="COR-001",
    name="recon_sensitive_access_exfil",
    description=(
        "Agent performed reconnaissance, accessed sensitive data, "
        "then attempted exfiltration within the correlation window."
    ),
    severity="critical",
    conditions=[_is_recon_event, _is_sensitive_access, _is_exfil_attempt],
    window_seconds=300,
    mitre_tactic="TA0010",
    mitre_technique="T1567",
    min_events=3,
)

INJECTION_THEN_ESCALATION_RULE = CorrelationRule(
    rule_id="COR-002",
    name="injection_then_privilege_escalation",
    description=(
        "Prompt injection attempt followed by process-spawn or "
        "privilege escalation attempt within the same session."
    ),
    severity="critical",
    conditions=[_is_injection_attempt, _is_privilege_escalation],
    window_seconds=120,
    mitre_tactic="TA0004",
    mitre_technique="T1059",
    min_events=2,
)

SHADOW_SERVER_EXFIL_RULE = CorrelationRule(
    rule_id="COR-003",
    name="shadow_server_then_exfil",
    description=(
        "Connection to unregistered/shadow MCP server followed by "
        "exfiltration attempt. Indicates tool-call redirection attack."
    ),
    severity="critical",
    conditions=[_is_server_trust_violation, _is_exfil_attempt],
    window_seconds=180,
    mitre_tactic="TA0010",
    mitre_technique="T1199",
    min_events=2,
)

PERSISTENT_ATTACKER_RULE = CorrelationRule(
    rule_id="COR-004",
    name="persistent_blocked_attempts",
    description=(
        "Multiple high-risk blocked attempts from the same session. "
        "Indicates an attacker probing for bypasses."
    ),
    severity="high",
    conditions=[_is_repeated_block, _is_repeated_block, _is_repeated_block],
    window_seconds=60,
    mitre_tactic="TA0001",
    mitre_technique="T1190",
    min_events=3,
)

INJECTION_THEN_EXFIL_RULE = CorrelationRule(
    rule_id="COR-005",
    name="injection_then_exfil",
    description=(
        "Prompt injection attempt followed by data exfiltration "
        "attempt. Classic indirect prompt injection attack chain."
    ),
    severity="critical",
    conditions=[_is_injection_attempt, _is_exfil_attempt],
    window_seconds=180,
    mitre_tactic="TA0010",
    mitre_technique="T1567",
    min_events=2,
)

SENSITIVE_THEN_SHADOW_RULE = CorrelationRule(
    rule_id="COR-006",
    name="sensitive_access_then_shadow_server",
    description=(
        "Agent accessed sensitive data then connected to an "
        "unregistered MCP server. Possible data staging."
    ),
    severity="high",
    conditions=[_is_sensitive_access, _is_server_trust_violation],
    window_seconds=120,
    mitre_tactic="TA0009",
    mitre_technique="T1074",
    min_events=2,
)


# All built-in rules
BUILTIN_RULES: list[CorrelationRule] = [
    RECON_TO_EXFIL_RULE,
    INJECTION_THEN_ESCALATION_RULE,
    SHADOW_SERVER_EXFIL_RULE,
    PERSISTENT_ATTACKER_RULE,
    INJECTION_THEN_EXFIL_RULE,
    SENSITIVE_THEN_SHADOW_RULE,
]
