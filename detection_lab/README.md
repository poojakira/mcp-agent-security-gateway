# Detection Engineering Lab

Lab environment for practicing detection engineering against MCP agent security events.

This is a **learning and practice environment**, not a production SIEM deployment. It demonstrates real detection engineering patterns (ECS formatting, correlation rules, log shipping, attack simulation, detection rule authoring) against the MCP security gateway's event stream.

## What This Lab Includes

| Component | Purpose |
|-----------|---------|
| `src/mcp_monitor/siem/ecs_formatter.py` | Transforms gateway decisions into Elastic Common Schema (ECS 8.x) events |
| `src/mcp_monitor/siem/correlation.py` | In-memory correlation engine with 6 built-in multi-event attack rules |
| `src/mcp_monitor/siem/shipper.py` | Log shipping to Elasticsearch (bulk API), NDJSON files (for Filebeat), or stdout |
| `src/mcp_monitor/siem/attack_simulations.py` | Atomic Red Team style attack scenarios that generate detectable events |
| `detection_rules/elastic_rules.toml` | 9 Elastic Security detection rules with MITRE ATT&CK mapping |
| `detection_lab/filebeat.yml` | Filebeat config to ship gateway NDJSON to Elasticsearch |
| `docker-compose.detection-lab.yml` | Full ELK stack + gateway for local detection practice |
| `tests/test_siem.py` | Tests for ECS formatting, correlation, and shipping |

## Architecture

```
MCP Security Gateway
        |
        | (security decisions: allow/block/redact/quarantine)
        v
+------------------+
| ECS Formatter    |  Transforms decisions to Elastic Common Schema
+------------------+
        |
   +----+----+
   |         |
   v         v
+------+  +----------+
| File |  | Elastic  |  NDJSON file or direct ES bulk API
| Ship |  | Shipper  |
+------+  +----------+
   |         |
   v         v
+------+  +----------+
| File |  | Elastic  |  Filebeat picks up NDJSON
| beat |  | search   |
+------+  +----------+
        \    |
         \   |
          v  v
      +---------+
      | Kibana  |  Detection rules, dashboards, alerts
      +---------+
```

Separately, the **Correlation Engine** runs in-process and evaluates multi-event patterns:

```
Security Events (stream)
        |
        v
+-------------------+
| Correlation       |  Sliding window per session
| Engine            |  6 built-in rules
+-------------------+
        |
        v
Correlation Matches (alerts for multi-step attacks)
```

## Correlation Rules

| Rule ID | Name | Pattern | Severity |
|---------|------|---------|----------|
| COR-001 | recon_sensitive_access_exfil | Recon + sensitive data access + exfiltration attempt | Critical |
| COR-002 | injection_then_privilege_escalation | Prompt injection + process spawn attempt | Critical |
| COR-003 | shadow_server_then_exfil | Unregistered server + exfiltration | Critical |
| COR-004 | persistent_blocked_attempts | 3+ high-risk blocks in 60 seconds | High |
| COR-005 | injection_then_exfil | Prompt injection + exfiltration attempt | Critical |
| COR-006 | sensitive_access_then_shadow_server | Sensitive access + unregistered server | High |

## Attack Simulations

```bash
# List available scenarios
python -m mcp_monitor.siem.attack_simulations --list

# Run all attack simulations
python -m mcp_monitor.siem.attack_simulations --scenario all

# Run a specific scenario
python -m mcp_monitor.siem.attack_simulations --scenario SIM-002

# Output as JSON (for pipeline integration)
python -m mcp_monitor.siem.attack_simulations --json --quiet
```

### Available Scenarios

| ID | Name | MITRE Tactic | Steps |
|----|------|-------------|-------|
| SIM-001 | Basic Prompt Injection | TA0002 Execution | 3 |
| SIM-002 | Reconnaissance to Exfiltration Chain | TA0010 Exfiltration | 3 |
| SIM-003 | Shadow MCP Server Redirection | TA0001 Initial Access | 2 |
| SIM-004 | Injection then Privilege Escalation | TA0004 Privilege Escalation | 2 |
| SIM-005 | PII Leakage Through Tool Calls | TA0009 Collection | 2 |
| SIM-006 | Persistent Probing (Bypass Attempts) | TA0043 Reconnaissance | 4 |

## Quick Start

### Run the detection lab locally

```bash
# Start the full stack
docker compose -f docker-compose.detection-lab.yml up -d

# Wait for Elasticsearch to be ready
curl -s http://localhost:9200/_cluster/health | python -m json.tool

# Run attack simulations to generate events
python -m mcp_monitor.siem.attack_simulations --scenario all

# Open Kibana
# http://localhost:5601
# Navigate to: Security > Alerts
```

### Run without Docker (tests only)

```bash
# Install the package
pip install -e ".[dev,server]"

# Run SIEM tests
pytest tests/test_siem.py -v

# Run correlation engine directly
python -c "
from mcp_monitor.siem.correlation import CorrelationEngine, BUILTIN_RULES, SecurityEvent
import time

engine = CorrelationEngine()
engine.add_rules(BUILTIN_RULES)

# Simulate injection then escalation
engine.ingest(SecurityEvent(
    timestamp=time.time(),
    event_type='block',
    session_id='test',
    findings=['prompt_injection_detected'],
))
matches = engine.ingest(SecurityEvent(
    timestamp=time.time(),
    event_type='block',
    session_id='test',
    layer_name='process_spawn',
    findings=['subprocess_detected'],
))
print(f'Correlation matches: {len(matches)}')
for m in matches:
    print(f'  {m.rule_id}: {m.rule_name} (severity={m.severity})')
"
```

## Elastic Detection Rules

Import `detection_rules/elastic_rules.toml` into Kibana:

```
Kibana > Security > Rules > Import rules
```

Or use the Elastic Detection Rules API:

```bash
# Convert TOML to Kibana NDJSON format (requires elastic-detection-rules CLI)
# Or manually create rules matching the queries in elastic_rules.toml
```

## Scope and Limitations

This is a lab environment. Specific limitations:

- **Single-node Elasticsearch**: no high availability, no persistence guarantees
- **No TLS**: all communication is unencrypted (lab only)
- **No authentication on Elasticsearch/Kibana**: default open access
- **In-memory correlation**: state is lost on gateway restart
- **Filebeat single-instance**: no guaranteed delivery under high volume
- **Detection rules are pattern-based**: they catch the specific attack simulations, not all possible attacks
- **Not load-tested**: throughput limits unknown

## What This Demonstrates

For detection engineering practice:

1. **Event normalization**: transforming application-specific security decisions into a standard schema (ECS)
2. **Correlation**: detecting multi-step attacks that are invisible when examining events individually
3. **Detection rule authoring**: writing KQL, EQL, and threshold rules against security events
4. **Attack simulation**: structured, repeatable tests that validate detection coverage
5. **Log pipeline**: end-to-end flow from security control to SIEM to alert
6. **MITRE ATT&CK mapping**: connecting detections to established threat taxonomy

## Testing

```bash
pytest tests/test_siem.py -v
```

Tests cover:
- ECS event formatting (10 tests)
- Correlation rule matching and non-matching (8 tests)
- Session isolation and window expiry
- File and stdout log shipping
- Statistics tracking
