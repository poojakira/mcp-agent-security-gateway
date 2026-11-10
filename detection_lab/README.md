# Detection Engineering Lab

> **Evidence and release status (2026-11-09):** This is an isolated detection and telemetry laboratory. CI uses a mandatory operator-supplied local key and loopback-bound published ports; this does not turn Kibana, Elasticsearch or the MCP gateway into a supported external production service. The [release review](../docs/review/PHASE13_RELEASE_READINESS.md) remains **NO-GO**, and [PR #167](https://github.com/poojakira/mcp-agent-security-gateway/pull/167) is a draft integration candidate.
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

**Docker Engine safety:** Use Docker Engine **28.0.0 or newer** for the loopback-only published ports, or enforce equivalent host firewall restrictions that prevent access from other devices on the local network. Do not expose the unauthenticated Elasticsearch/Kibana lab to shared or public networks. These examples are local-only, not a production deployment.

The lab requires a locally generated `MCP_API_KEY`; the formerly shared key has been removed from active Compose configuration but remains in Git history. If that shared key was reused in any running gateway, isolate the affected instance, replace the credential in the deployment secret store, and **recreate** the service or roll new pods. A plain `docker compose restart` does not apply changed environment variables. The bundled Elasticsearch/Kibana configuration disables authentication and is **local-lab only**.

```bash
# Create a NEW secret for your local gateway. Never reuse the previously
# committed demonstration key: it remains visible in Git history.
export MCP_API_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"

# Optionally persist a newly generated lab-only credential outside the repository:
umask 077
mkdir -p "$HOME/.config/mcp-gateway"
printf '%s' "$MCP_API_KEY" > "$HOME/.config/mcp-gateway/detection-lab-key"
chmod 600 "$HOME/.config/mcp-gateway/detection-lab-key"
# In a later shell, reload that same local credential before Compose commands:
# export MCP_API_KEY="$(cat "$HOME/.config/mcp-gateway/detection-lab-key")"
# Never commit, paste, log, or publish the credential file.

# Start the full stack (ports bind to 127.0.0.1, not the public interface)
docker compose -f docker-compose.detection-lab.yml up -d

# After a rotation, recreate to apply changed environment rather than 'restart':
# docker compose -f docker-compose.detection-lab.yml up -d --force-recreate mcp-gateway
# Confirm the retired credential is rejected without printing it into logs.

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

## Verification Status

Verified on Docker Desktop 29.1.3 (Windows, 8 GB allocated to Docker) on 2026-08-27:

- **SIEM unit tests**: 21/21 pass (`pytest tests/test_siem.py`)
- **Correlation engine**: fires COR-002 on injection-then-escalation (standalone, no services)
- **Attack simulation CLI**: `--list` works; against a stopped gateway it correctly reports `connection_error`
- **Elasticsearch**: single-node stack reaches green status
- **Filebeat end-to-end**: ECS events written by `FileShipper` are shipped to Elasticsearch and are queryable via `GET /mcp-security-events*/_count`, with all ECS fields (`event.action`, `mcp.enforcement_action`, `threat.technique.id`) preserved. Confirmed 0 Filebeat errors with the committed config.

Two configuration fixes were required to make Filebeat work under Docker Desktop and were applied to this repo:

1. `--strict.perms=false` on the Filebeat command. Bind-mounted config files appear world-writable on Windows/macOS, which Filebeat otherwise rejects.
2. `setup.template.enabled: false` and `setup.ilm.enabled: false` in `filebeat.yml`. Without these, Filebeat 8.x tries to provision a data-stream template and fails with "no matching index template found". With them, Elasticsearch auto-creates the data stream on first write.

**Not independently load-tested**: throughput limits, multi-node behavior, and Kibana alert-rule execution (as opposed to event ingestion) were not measured.

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

## Credential and exposure safety

Supply a fresh local lab-only `MCP_API_KEY` when Compose requires it. Never reuse historical public demonstration credentials. The Compose release gate tests for loopback-published ports; verify the resolved configuration before starting services. Deleting a key from source does not rotate or revoke a credential at a service issuer.
