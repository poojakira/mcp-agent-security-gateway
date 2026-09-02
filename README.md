# MCP Agent Security Gateway

**Security controls for MCP tool calls, agent-to-tool interactions, and AI agent execution boundaries.**

[![CI](https://github.com/poojakira/mcp-agent-security-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/poojakira/mcp-agent-security-gateway/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)

I built this project around a security question that becomes increasingly important as AI systems move from generating text to taking actions:

> **What should happen between an AI agent deciding to use a tool and that action actually being executed?**

When an agent can invoke MCP tools, access files, call APIs, interact with databases, send messages, or reach cloud and internal services, prompt filtering is no longer the entire security boundary.

I built **MCP Agent Security Gateway** to place explicit inspection, policy, and observability around that agent-to-tool boundary.

The project includes a real inline MCP stdio proxy, a real-time security control plane, a separate HTTP inspection service, and additional security-evaluation components for studying agent runtime behavior.

---

## What I Built

My work in this repository covers:

- MCP `tools/call` inspection
- JSON-RPC 2.0 parsing
- inline allow/block decisions
- prompt-injection detection
- Unicode and encoded-payload normalization
- MCP server trust and capability checks
- PII and sensitive-data signals
- exfiltration indicators
- tool-output inspection
- multi-layer policy evaluation
- process-event evaluation
- network-egress policy decisions
- SHA-256 hash-chained audit logging
- write-ahead logging
- tracing and metrics
- rate limiting
- circuit breakers
- shadow mode
- real-time security telemetry
- Docker and Kubernetes deployment templates
- adversarial and regression testing

I deliberately separate the different runtime paths in this README so that the capabilities I describe match the code that actually executes them.

---

# Why Agent Tool Security Matters

A traditional LLM interaction often looks like:

```text
User
  │
  ▼
Prompt
  │
  ▼
LLM
```

An agentic system introduces another security boundary:

```text
User
  │
  ▼
LLM / Agent
  │
  ▼
Decision to Act
  │
  ▼
Tool Invocation
  │
  ▼
MCP Server
  │
  ▼
Files · APIs · Databases · Cloud · Internal Services
```

That second boundary is the focus of this project.

I want to reason about questions such as:

- Which tool is the agent requesting?
- Which MCP server is associated with that request?
- What arguments is the agent sending?
- Do those arguments contain injection indicators?
- Is sensitive data present?
- Is the requested server expected?
- Is the requested capability consistent with that server?
- Does the requested destination violate configured policy?
- What information is returned to the agent?
- What security decision was made?
- Can I reconstruct that decision afterward?

My goal is to move agent security beyond prompt inspection and toward **action-aware security controls**.

---

# Architecture

The repository currently contains three primary runtime surfaces.

```text
                    ┌─────────────────────────────┐
                    │        AI Agent / MCP       │
                    │            Client           │
                    └──────────────┬──────────────┘
                                   │
               ┌───────────────────┼────────────────────┐
               │                   │                    │
               ▼                   ▼                    ▼
     ┌─────────────────┐  ┌──────────────────┐  ┌──────────────────┐
     │ Inline MCP      │  │ Real-Time        │  │ HTTP Inspection  │
     │ stdio Proxy     │  │ Control Plane    │  │ Service          │
     │                 │  │ :8000            │  │ :8080            │
     └────────┬────────┘  └────────┬─────────┘  └────────┬─────────┘
              │                    │                     │
              ▼                    ▼                     ▼
       Downstream MCP       5-Layer Decision       Broader Security
           Server                Pipeline             Inspection
```

These paths share security concepts and components, but they serve different purposes.

---

# 1. Inline MCP stdio Proxy

I implemented a real stdio MCP proxy that can sit between an MCP client and a downstream MCP server.

```text
MCP Client
    │
    │ JSON-RPC over stdio
    ▼
┌───────────────────────────────┐
│ MCP Agent Security Gateway    │
│                               │
│ Parse JSON-RPC                │
│ Identify tools/call           │
│ Normalize arguments           │
│ Inspect security signals      │
│ Allow or Block                │
└───────────────┬───────────────┘
                │
         allowed request
                │
                ▼
        Downstream MCP Server
```

For MCP `tools/call` requests, I inspect the request before it is forwarded.

When the proxy produces a blocking decision, the request is not sent to the downstream server. Instead, the proxy returns a JSON-RPC security error.

Normal non-tool protocol messages such as initialization and `tools/list` pass through.

The current stdio path primarily focuses on JSON-RPC parsing and prompt-injection-oriented tool-argument inspection.

---

## Run the Inline Proxy

Clone and install:

```bash
git clone https://github.com/poojakira/mcp-agent-security-gateway.git
cd mcp-agent-security-gateway

python -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -e ".[dev,server]"
```

On Windows PowerShell:

```powershell
git clone https://github.com/poojakira/mcp-agent-security-gateway.git
cd mcp-agent-security-gateway

py -m venv .venv
.\.venv\Scripts\Activate.ps1

py -m pip install --upgrade pip
py -m pip install -e ".[dev,server]"
```

Verify the package:

```bash
python -c "import mcp_monitor; print('OK')"
```

Run a downstream MCP server through the proxy:

```bash
python -m mcp_monitor.proxy.stdio_proxy -- <server-command> [args...]
```

Example:

```bash
python -m mcp_monitor.proxy.stdio_proxy -- \
  npx -y @modelcontextprotocol/server-filesystem /path/to/allowed/directory
```

---

# Claude Desktop Integration

For a stdio MCP server, I can place the proxy directly in front of the downstream process.

Example configuration:

```json
{
  "mcpServers": {
    "secured-filesystem": {
      "command": "python",
      "args": [
        "-m",
        "mcp_monitor.proxy.stdio_proxy",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/path/to/allowed/directory"
      ]
    }
  }
}
```

The execution path becomes:

```text
Claude Desktop
      │
      ▼
MCP Agent Security Gateway
      │
      ▼
Downstream MCP Server
      │
      ▼
Tool
```

This allows the gateway to make a security decision before selected MCP tool calls reach the downstream process.

---

# 2. Real-Time Security Control Plane

I also built a FastAPI-based control plane for evaluating submitted agent tool calls and visualizing security decisions.

Start it with:

```bash
python run_realtime.py
```

On Windows:

```powershell
py -X utf8 run_realtime.py
```

Default endpoint:

```text
http://127.0.0.1:8000
```

The control plane exposes surfaces including:

```text
/             security dashboard
/docs         FastAPI documentation
/api/scan     tool-call evaluation
/api/stats    decision statistics
/ws           real-time event stream
```

---

## Submit a Tool Call

Example:

```bash
curl -X POST http://127.0.0.1:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "name": "email.send",
    "server_id": "postmark",
    "arguments": {
      "to": "operator@example.com",
      "bcc": "unexpected@example.net"
    }
  }'
```

The request is evaluated through the control plane's security decision pipeline.

The resulting event includes information such as:

```text
tool name
server ID
allowed / blocked
blocking layer
risk score
findings
decision latency
per-layer latency
```

I keep externally submitted events separate from the optional demo workload so that simulated traffic is not presented as production telemetry.

---

# Demo Mode

The control plane includes an opt-in synthetic workload for testing the dashboard and event pipeline.

Linux/macOS:

```bash
MCP_DEMO_MODE=1 python run_realtime.py
```

Windows PowerShell:

```powershell
$env:MCP_DEMO_MODE = "1"
py -X utf8 run_realtime.py
```

Demo events are identified as demo traffic in telemetry.

I use this mode for visualization and regression testing, not as evidence of real-world traffic volume or attack prevalence.

---

# Python Tool Integration

I provide a `GatewayClient` wrapper that can submit a tool call to the control plane before a Python tool function executes.

Example:

```python
from mcp_monitor.client import GatewayClient, ToolBlocked

gateway = GatewayClient("http://localhost:8000")

@gateway.guard
def send_email(*, server_id: str, to: str, body: str) -> str:
    return "sent"

try:
    result = send_email(
        server_id="postmark",
        to="user@example.com",
        body="Hello",
    )
    print(result)

except ToolBlocked as error:
    print(error.verdict)
```

The wrapper constructs a tool-call object and submits it to `/api/scan`.

If the returned decision contains:

```text
allowed = false
```

the wrapper raises `ToolBlocked` before the wrapped function executes.

Transport failures currently propagate to the caller, allowing the integrating application to decide how it wants to handle gateway unavailability.

---

# Five-Layer Decision Pipeline

The real-time control plane uses a composable five-layer decision architecture.

```text
Tool Call
   │
   ▼
Layer 1
Server Registry / Trust Decision
   │
   ▼
Layer 2
Inline Tool-Call Policy
   │
   ▼
Layer 3
Process-Spawn Intent Evaluation
   │
   ▼
Layer 4
Semantic Intent Analysis
   │
   ▼
Layer 5
Network Egress Policy Decision
   │
   ▼
Allow / Block Verdict
```

---

## Layer 1 — Server Registry

I maintain a server-registration model that can identify calls associated with unexpected server identifiers.

When a known-server registry is configured, an unregistered server can be rejected at this layer.

This is an application-level trust control around MCP server identity.

---

## Layer 2 — Inline Tool-Call Policy

This layer evaluates the submitted tool call against proxy policy.

The policy model supports decisions including:

```text
ALLOW
BLOCK
REDACT
QUARANTINE
```

The decision is made over the supplied tool-call representation before later layers are evaluated.

---

## Layer 3 — Process-Spawn Intent Evaluation

Layer 3 examines supplied tool arguments for process-execution indicators.

Examples include strings associated with:

```text
subprocess
os.system
/bin/sh
bash -c
cmd.exe /c
```

This is **application-level argument analysis**.

It does not claim that the gateway independently hooks or intercepts operating-system syscalls.

---

## Layer 4 — Semantic Intent Analysis

This layer evaluates selected tool-call content for suspicious semantic behavior.

Examples include patterns associated with:

- hidden recipients
- exfiltration-oriented intent
- suspicious forwarding behavior
- covert recipient behavior
- encoded content patterns

This complements deterministic rule checks with higher-level intent analysis.

---

## Layer 5 — Network Egress Policy Decision

I implemented an egress-policy decision engine that evaluates requested network destinations.

Policy can consider:

- allowed domains
- blocked domains
- allowed IP addresses
- blocked IP addresses
- allowed ports
- payload-size limits
- default-deny behavior

The result is an:

```text
ALLOW
```

or:

```text
DENY
```

policy decision.

This component is a **policy engine**, not a packet-filtering firewall.

It does not independently intercept network packets or arbitrary socket connections generated by a downstream MCP process.

Actual network enforcement would require integrating the returned policy decision with a runtime or network control capable of enforcing it.

---

# Process Event Evaluation

The repository also contains process-event evaluation logic.

The current component accepts `SyscallEvent` objects supplied by the caller and evaluates them against configured behavioral policy.

Examples of represented event categories include:

- process spawn
- file access
- network connection
- DNS resolution
- socket send

The component evaluates the event objects it receives.

It does not independently install operating-system hooks through technologies such as:

```text
eBPF
auditd
ETW
ptrace
kernel modules
```

I use this component to explore how runtime/process context could contribute to agent security decisions.

---

# 3. HTTP Security Inspection Service

I also implemented a separate HTTP inspection service.

Its default listener is:

```text
127.0.0.1:8080
```

Start it with:

```bash
export MCP_API_KEY="replace-with-a-secret"
export MCP_ALLOWED_SERVERS="postmark,filesystem"

mcp-gateway
```

The service exposes:

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/v1/inspect_call` | Evaluate a proposed tool call |
| `POST` | `/v1/inspect_output` | Evaluate tool output |
| `GET` | `/v1/health` | Health check |
| `GET` | `/v1/ready` | Readiness check |
| `GET` | `/v1/metrics` | Prometheus-style metrics |

The inspection endpoints require API-key authentication unless anonymous mode is explicitly enabled.

---

## Example Inspection Request

```bash
curl -X POST http://127.0.0.1:8080/v1/inspect_call \
  -H "Content-Type: application/json" \
  -H "X-API-Key: replace-with-a-secret" \
  -d '{
    "name": "email.send",
    "server_id": "postmark",
    "arguments": {
      "to": "user@example.com",
      "body": "Example message"
    }
  }'
```

The service returns a structured decision containing fields such as:

```text
allowed
risk_score
findings
call_id
trace_id
span_id
```

I intentionally leave the exact values out of this README because they should be reproduced against the current code rather than presented as a static demonstration result.

The service is a **security decision API**.

The integrating runtime remains responsible for enforcing the returned decision before performing the actual tool action.

---

# Core Security Inspection

The broader inspection path combines multiple detector families.

---

## Prompt-Injection Detection

I implemented prompt-injection inspection for content inside tool-call arguments.

The detector includes **50+ rule patterns** across areas such as:

- instruction override
- prompt extraction
- role manipulation
- jailbreak-oriented phrases
- delimiter injection
- HTML and Markdown injection
- encoded instructions
- command-oriented payloads
- indirect-injection indicators
- obfuscation attempts

Before matching, input normalization includes mechanisms such as:

- zero-width character removal
- bidirectional-control handling
- Unicode normalization
- selected Cyrillic and Greek homoglyph normalization
- Base64 decoding attempts
- ROT13 heuristics

The repository also contains an optional ML-assisted detection path.

I treat these mechanisms as security signals rather than claiming universal prompt-injection prevention.

---

# MCP Server Trust and Capabilities

I implemented server-registration and capability checks for submitted MCP tool calls.

A request can be flagged when:

- its `server_id` is missing
- its server is not expected
- a registered server attempts a capability outside its declared capabilities

Conceptually:

```text
Agent
  │
  ▼
Requested MCP Server
  │
  ▼
Expected server?
  │
  ├── No  → Flag / Deny
  │
  └── Yes
       │
       ▼
Expected capability?
       │
       ├── No  → Flag / Deny
       │
       └── Yes → Continue
```

This is one area where my work moves beyond prompt inspection toward **agent authorization and capability boundaries**.

---

# Sensitive-Data Inspection

I implemented heuristic detection for selected sensitive-data patterns.

Current tests cover data types including:

- email addresses
- Social Security number patterns
- credit-card-like values
- phone numbers
- IP addresses
- dates of birth
- passport-like identifiers
- AWS access-key patterns
- API-key-like values

The detector can also redact selected matched values.

I treat this as a security signal rather than a replacement for an enterprise DLP platform.

---

# Exfiltration Signals

I implemented rule-based checks for selected exfiltration indicators.

Examples include:

- hidden/BCC recipients
- suspicious email headers
- oversized payloads
- large Base64-like blobs
- raw-IP destinations
- selected suspicious outbound URLs

These findings identify suspicious patterns.

They do not by themselves prove malicious intent.

---

# Tool-Output Inspection

The HTTP inspection service can also evaluate tool outputs through:

```text
POST /v1/inspect_output
```

This path evaluates selected output data for:

- sensitive-data signals
- exfiltration indicators
- associated risk findings

I built this because I view agent/tool security as a bidirectional boundary:

```text
Agent
  │
  │ Tool Request
  ▼
Security Decision
  │
  ▼
Tool
  │
  │ Tool Output
  ▼
Security Inspection
  │
  ▼
Agent
```

Security should reason about both:

> **What is the agent allowed to send?**

and:

> **What is the tool allowed to return?**

---

# Authentication

Protected HTTP inspection endpoints require:

```text
X-API-Key
```

unless anonymous mode is explicitly enabled.

Anonymous mode can be configured using:

```bash
MCP_ALLOW_ANONYMOUS=true
```

If authentication is required but no API key is configured, protected inspection requests are rejected.

---

# Rate Limiting

I implemented request-rate limiting around the HTTP inspection service.

Operational endpoints such as:

```text
/v1/health
/v1/ready
/v1/metrics
```

are handled separately so monitoring and readiness checks remain accessible under normal inspection load.

---

# Circuit Breakers

I use separate circuit breakers around call inspection and output inspection.

When the relevant circuit is open, the configured fallback produces a deny decision rather than silently treating the request as safe.

I scope this fail-closed behavior specifically to the circuit-breaker fallback path.

---

## Failure Semantics

| Failure Scenario | Expected Behavior | Scope | Tested? |
|---|---|---|---|
| Detector unavailable | Circuit breaker opens → DENY | HTTP inspection path | ✅ (circuit breaker tests) |
| Request timeout | Configurable timeout → propagates to caller | All paths | ✅ |
| Malformed JSON-RPC | Parse error returned to client | stdio proxy | ✅ |
| Policy engine unavailable | Circuit breaker → DENY | HTTP inspection | ✅ |
| Audit logger unavailable | Inspection continues, audit gap logged | All paths | Partial |
| Missing API key config | Rejects protected requests (401) | HTTP inspection | ✅ |
| Downstream MCP server crash | Connection error propagates | stdio proxy | ✅ |

---

# Shadow Mode

The HTTP inspection service supports shadow mode:

```bash
export MCP_SHADOW_MODE=true
```

In shadow mode, the service still evaluates the request and records the original findings, but the returned decision is changed to allow.

I use shadow mode to separate:

```text
policy observation
```

from:

```text
policy enforcement
```

before enabling blocking behavior.

---

# Auditability

I implemented SHA-256 hash-chained audit logging for security decisions.

Conceptually:

```text
Entry 1
   │
   │ hash
   ▼
Entry 2
   │
   │ hash
   ▼
Entry 3
```

Each entry can reference the previous entry's hash.

Verification can detect inconsistent modification of historical entries.

I describe this as:

> **tamper-evident audit logging**

rather than claiming immutable storage or cryptographic non-repudiation.

---

# Write-Ahead Logging

Protected HTTP inspection requests are recorded to a write-ahead log before inspection processing.

Recorded metadata includes values such as:

- endpoint path
- request-body SHA-256
- body size
- trace ID
- span ID

I use this to strengthen traceability around security-sensitive requests.

---

# Observability

The HTTP inspection service includes operational instrumentation for:

- structured logging
- trace IDs
- span IDs
- W3C-style `traceparent` propagation
- request counters
- error counters
- request-latency measurements
- active-request tracking
- circuit-breaker state
- health checks
- readiness checks
- Prometheus-style metrics
- optional webhook alerts

The real-time control plane also tracks:

- external vs demo event sources
- tool attribution
- server attribution
- blocking layer
- decision latency
- recent event rate

I consider observability part of the security boundary because security decisions should be inspectable and explainable.

---

# Advanced Agent Security Research

I also maintain additional security components for exploring more complex agentic attack paths.

---

## Cross-Tool Correlation

Some attacks only become visible when multiple actions are examined together.

For example:

```text
read_sensitive_data()
        │
        ▼
Agent receives data
        │
        ▼
email.send()
        │
        ▼
External destination
```

The individual calls can look different in isolation.

I maintain correlation logic for identifying selected multi-tool sequences and data-flow relationships.

---

## Tool Manifest Integrity

I maintain logic for comparing expected tool definitions with later representations.

The checks can identify selected changes in:

- tool descriptions
- parameters
- schemas
- capabilities

I use this to explore security around unexpected tool-definition changes and capability drift.

---

## Behavioral Drift

I experiment with detecting unexpected changes in:

- fields
- output structure
- payload structure
- payload size
- observed tool behavior

These components are research and evaluation mechanisms rather than claims of complete production anomaly detection.

---

## Security Invariants

I maintain deterministic security invariants for selected behaviors.

Examples include:

```text
unexpected hidden email recipients
selected destructive database behavior
raw-IP URL usage
shell-oriented arguments
```

I am interested in combining deterministic invariants with heuristic detection because not every security decision should depend on probabilistic classification.

---

## Canary Validation

I maintain known-input and expected-output probes for evaluating selected changes in tool behavior.

These experiments help me reason about whether a tool continues behaving within an expected security baseline.

---

## Sandboxing Research

The repository contains sandbox-related experiments for restricting selected high-risk execution.

I treat these as experimental isolation work rather than presenting them as a complete production sandbox.

---

# Configuration

Important environment variables for the port `8080` inspection service include:

| Variable | Default | Purpose |
|---|---:|---|
| `MCP_LISTEN_HOST` | `127.0.0.1` | HTTP bind address |
| `MCP_LISTEN_PORT` | `8080` | HTTP service port |
| `MCP_API_KEY` | unset | Protected endpoint authentication |
| `MCP_ALLOW_ANONYMOUS` | `false` | Explicit anonymous mode |
| `MCP_SHADOW_MODE` | `false` | Observation without returned blocking |
| `MCP_RATE_LIMIT_RPM` | `1000` | Request-rate configuration |
| `MCP_MAX_PAYLOAD_KB` | `100` | Maximum HTTP payload |
| `MCP_ALLOWED_SERVERS` | empty | Expected MCP server IDs |
| `MCP_WEBHOOK_URL` | unset | Optional alert destination |
| `MCP_CIRCUIT_BREAKER_THRESHOLD` | `5` | Circuit-breaker threshold |
| `MCP_CIRCUIT_BREAKER_TIMEOUT` | `30` | Recovery timeout |
| `MCP_LOG_LEVEL` | `INFO` | Runtime logging |
| `MCP_WAL_PATH` | temporary path | WAL location |
| `MCP_AUDIT_PATH` | temporary path | Audit-log location |

---

# Testing

Install development dependencies:

```bash
python -m pip install -e ".[dev,server]"
```

Run the complete test suite:

```bash
pytest tests/ -v
```

Run with coverage:

```bash
pytest tests/ \
  --cov=mcp_monitor \
  --cov-report=term-missing
```

---

# Verified Engineering Evidence

I validate the project through automated tests and security-focused CI rather than relying only on implementation claims.

For the currently verified commit:

```text
cafad51bce76620ec221c440f332bc46f199b9f0
```

the local test run and GitHub Actions pipeline validate the suite.

### Python 3.12

```text
622 tests collected
622 tests passed
```

The count increased from the earlier 595 baseline after adding 27 protocol/transport hardening tests (`tests/test_protocol_hardening.py` plus additions to `tests/test_client.py`) covering malformed/oversized/deeply-nested JSON-RPC inputs, unicode edge cases, and fail-closed client behaviour. Coverage is measured and gated in CI; the Elasticsearch HTTP shipper and the manually-run attack-simulation CLI are exercised in the detection lab rather than unit tests (see `detection_lab/README.md`).

The CI pipeline also completed successfully for:

- Python 3.10 tests
- Python 3.11 tests
- Python 3.12 tests
- Ruff linting
- Ruff formatting checks
- Pyright type checking
- Bandit security analysis
- `pip-audit`
- CodeQL
- Trivy
- Grype
- Syft SBOM generation
- Windows control-plane validation
- Docker image build

I scope these results to the tested commit.

They are reproducible software-engineering evidence, not a claim that automated tests can prove universal security effectiveness.

---

# Docker

The repository contains a multi-stage Docker build for the HTTP inspection service.

Build:

```bash
docker build -t mcp-agent-security-gateway .
```

Run:

```bash
docker run \
  -p 8080:8080 \
  -e MCP_API_KEY="replace-with-a-secret" \
  -e MCP_ALLOWED_SERVERS="postmark,filesystem" \
  mcp-agent-security-gateway
```

The Docker build runs the repository test suite in its builder stage before producing the runtime package.

The current CI pipeline successfully builds the Docker image.

---

# Kubernetes

Deployment templates are available under:

```text
deploy/k8s/
```

The repository contains manifests covering:

- Namespace
- Deployment
- Service
- ConfigMap
- HorizontalPodAutoscaler
- PersistentVolumeClaim
- secret example
- liveness probes
- readiness probes
- container security context

I treat these as deployment templates that can be adapted to a target environment.

---

# Current Scope

I keep a few implementation boundaries explicit because they are important to understanding the architecture.

### Runtime paths

The stdio proxy, real-time control plane, and HTTP inspection service are separate execution paths. They share security concepts, but not every control is active in every path.

### Inline proxy scope

The stdio proxy currently has a narrower inspection path than the broader HTTP/control-plane components.

### Process-event scope

Process-event components evaluate events or tool-call data supplied to them. They do not currently perform independent OS syscall hooking.

### Egress-policy scope

The egress component returns network policy decisions. It is not a packet-filtering firewall.

### Detection scope

The detectors are security controls and evaluation mechanisms. Like other heuristic detection systems, they can produce false positives and false negatives.

### Evidence scope

CI results, synthetic workloads, and adversarial fixtures demonstrate reproducible software behavior under defined conditions. I do not present them as production traffic or universal real-world detection rates.

---

# Known Limitations

1. **Not globally fail-closed**: Fail-closed behavior is scoped specifically to the circuit-breaker fallback path. Other failure modes (e.g., audit logger unavailable) do not block requests.
2. **Detection is heuristic**: Prompt-injection detection, PII detection, and exfiltration signals can produce false positives and false negatives. They are security signals, not guarantees.
3. **Enforcement is external**: The gateway returns security decisions. The integrating runtime must honor and enforce those decisions before executing tool actions.
4. **No OS-level hooking**: Process-event evaluation operates on supplied event objects. It does not independently install eBPF, auditd, ETW, or kernel-level hooks.
5. **Egress policy is advisory**: The network egress policy engine returns ALLOW/DENY decisions but does not intercept packets or socket connections.
6. **Audit gap under logger failure**: If the audit logger becomes unavailable, inspection continues but audit entries may be lost during the gap.
7. **Single-node state**: Circuit breaker state, rate limiter counters, and audit chains are per-process. Distributed deployments require external coordination.
8. **ML detector optional**: The ML-assisted prompt-injection path is optional and not active by default.

---

# Detection Engineering Lab

The `src/mcp_monitor/siem/` module and the `detection_lab/` directory provide a lab environment for practicing detection engineering against the gateway's security event stream. This is a lab, not a production SIEM deployment.

Components:

- **ECS formatter** (`siem/ecs_formatter.py`): transforms gateway security decisions into Elastic Common Schema (ECS 8.x) events with MITRE ATT&CK threat mapping.
- **Correlation engine** (`siem/correlation.py`): in-memory, per-session sliding-window engine with 6 built-in rules that detect multi-event attack chains (for example, recon then sensitive-data access then exfiltration) that are not visible when events are examined individually.
- **Log shippers** (`siem/shipper.py`): Elasticsearch bulk API, NDJSON file (for Filebeat pickup), and stdout backends.
- **Attack simulations** (`siem/attack_simulations.py`): 6 Atomic Red Team style scenarios that generate detectable events against a running gateway.
- **Detection rules** (`detection_rules/elastic_rules.toml`): 9 Elastic Security rules (KQL, EQL sequence, threshold) mapped to MITRE ATT&CK.
- **Lab stack** (`docker-compose.detection-lab.yml`, `detection_lab/filebeat.yml`): Elasticsearch, Kibana, and Filebeat wired to the gateway.

See [`detection_lab/README.md`](detection_lab/README.md) for the full walkthrough, correlation rule table, and scope limitations.

Quick validation (no external services required):

```bash
# Run the SIEM test suite (21 tests)
pytest tests/test_siem.py -v

# List the attack simulation scenarios
python -m mcp_monitor.siem.attack_simulations --list
```

The correlation engine and ECS formatter run without any external dependencies. The attack simulations require a running gateway (`python run_realtime.py`) because they submit tool calls to the control plane. The full ELK stack (`docker compose -f docker-compose.detection-lab.yml up -d`) requires Docker with at least 4 GB of memory available.

---

# Engineering Direction

I am continuing to evolve this project around one core idea:

> **Agent security should govern what an AI system is allowed to do, not only what it is allowed to say.**

My current engineering direction is focused on strengthening the security boundary between autonomous agents and the tools, services, and resources they can access.

Areas I am actively exploring include:

- **Agent identity and authorization** — connecting tool access to explicit workload identity, permissions, and capability boundaries
- **Runtime policy enforcement** — bringing more of the existing security controls into a unified agent-to-tool execution path
- **Execution isolation** — strengthening controls around high-risk tool and process execution
- **Agent-trajectory security** — correlating actions across multiple tool calls instead of evaluating every action independently
- **Security evaluation** — expanding adversarial testing and measurable evidence for agentic attack paths
- **Observability and audit** — making security decisions easier to trace, explain, and investigate

The architecture I am working toward is a security layer that can reason about:

> **Which agent is acting, which tool it wants to use, what resource it wants to access, whether that action is permitted, and how the decision can be audited afterward.**

---

# Repository Structure

```text
src/mcp_monitor/
├── proxy/          # Inline MCP stdio proxy
├── protocol/       # JSON-RPC / MCP parsing
├── detectors/      # Injection, PII, server trust, exfiltration
├── production/     # HTTP inspection service
├── server/         # Real-time control plane and dashboard
├── audit/          # Hash-chained audit log and WAL
├── layers/         # Composable security decision layers
├── advanced/       # Correlation, drift, manifests, canaries, invariants
├── defense10/      # Additional agent-security experiments
├── siem/           # SIEM integration: ECS formatter, correlation engine, log shippers, attack simulations
└── redteam/        # Adversarial evaluation components

tests/
deploy/k8s/
detection_rules/    # Elastic Security detection rules (MITRE ATT&CK mapped)
detection_lab/      # docker-compose ELK stack + Filebeat config
benchmark/
evidence/
```

---

# Project Documentation

I maintain supporting engineering documentation for operation, security review, and research context:

- [`RUNBOOK.md`](RUNBOOK.md) — setup, operation, testing, and deployment guidance
- [`SECURITY.md`](SECURITY.md) — security policy and vulnerability reporting
- [`SECURITY_AUDIT.md`](SECURITY_AUDIT.md) — security review and validation notes
- [`THREAT_MODEL.md`](THREAT_MODEL.md) — threat model, adversaries, attack surfaces, and mitigations
- [`detection_lab/README.md`](detection_lab/README.md) — detection engineering lab: SIEM integration, correlation rules, attack simulations
- [`RESEARCH_REPORT.md`](RESEARCH_REPORT.md) — technical research and supporting analysis

The repository's executable behavior is validated through its source code, automated tests, and CI pipeline.

---

# Verification

| Property | Value |
|---|---|
| Tested at commit | `cafad51bce76620ec221c440f332bc46f199b9f0` |
| Environment | Python 3.10 / 3.11 / 3.12, Ubuntu (CI), Windows (control-plane validation) |
| Last verified | 2026-08-27 |
| Tests | 569 |
| Coverage | 75% |

---

## License

MIT — see [LICENSE](LICENSE).

---

> **I do not think agent security ends at the prompt. I think the critical security boundary begins when an AI system is allowed to act.**
