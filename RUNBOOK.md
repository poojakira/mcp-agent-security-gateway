# Runbook — MCP Agent Security Gateway

## Runtime roles

This repository contains two deliberately different surfaces.

| Surface | Port | Role | Production enforcement? |
|---|---:|---|---|
| `mcp-gateway` production API | 8080 | authenticated MCP tool-call/output inspection | **Yes** |
| `run_realtime.py` dashboard | 8000 | local visualization/demo/control-plane development | No |

Do not deploy the port-8000 dashboard as the production policy-enforcement
boundary. The hardened deployment contract is the stdlib production API under
`src/mcp_monitor/production/`.

## Install for development

```bash
git clone https://github.com/poojakira/mcp-agent-security-gateway.git
cd mcp-agent-security-gateway
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,server]"
```

On Windows PowerShell use `.venv\Scripts\Activate.ps1`.

## Run tests and security checks

```bash
ruff check src tests run_realtime.py
ruff format --check src tests run_realtime.py
pytest tests/ -q --tb=short
bandit -r src -ll
pip-audit --skip-editable
```

Use the successful GitHub Actions run on the exact commit as the authoritative
verification record.

## Production configuration

Production mode validates security-critical settings at startup.

```bash
export MCP_ENV=production
# Configure either one legacy key or a stable multi-key set.
export MCP_API_KEY="$(openssl rand -hex 32)"
# export MCP_API_KEYS="<stable-key-a>,<stable-key-b>,<stable-key-c>"
export MCP_ALLOWED_SERVERS="github,filesystem"
export MCP_ALLOW_ANONYMOUS=false
export MCP_WAL_PATH=/var/lib/mcp/wal.jsonl
export MCP_AUDIT_PATH=/var/lib/mcp/audit.jsonl
export MCP_LISTEN_HOST=0.0.0.0
export MCP_LISTEN_PORT=8080
```

Production startup fails when:

- anonymous access is enabled;
- no API credential is configured, or any configured credential is shorter than 32 characters;
- WAL or audit paths are not configured;
- the approved-server set is empty;
- rate/payload limits are invalid.

## Docker Compose

Copy the example environment and replace its values:

```bash
cp .env.example .env
# edit .env with MCP_API_KEY or MCP_API_KEYS and the exact MCP_ALLOWED_SERVERS set
docker compose config >/dev/null
docker compose up -d --build
```

The Compose contract:

- binds the application to `0.0.0.0:8080` inside the container;
- exposes it only on host loopback by default;
- persists WAL/audit state on the `mcp-state` named volume;
- uses `/v1/ready` as the health gate.

## Kubernetes

The sample manifests under `deploy/k8s/` run one replica because the included
file-backed WAL/audit store is single-writer state. See
`deploy/k8s/README.md`.

For controlled deployment, pin the released image by digest rather than using a
mutable tag.

## Production API

Health and readiness are intentionally unauthenticated for orchestration.

```bash
curl http://127.0.0.1:8080/v1/health
curl http://127.0.0.1:8080/v1/ready
```

Inspection and metrics require `X-API-Key`. The supplied value may match the legacy `MCP_API_KEY` or any stable credential configured in `MCP_API_KEYS`.

```bash
curl -X POST http://127.0.0.1:8080/v1/inspect_call \
  -H "X-API-Key: $MCP_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name":"read_file",
    "server_id":"github",
    "arguments":{"path":"README.md"}
  }'

curl -H "X-API-Key: $MCP_API_KEY" \
  http://127.0.0.1:8080/v1/metrics
```

## Trusted source-address and external-validation telemetry

Source attribution is explicit and fail-safe:

- the socket peer address is authoritative by default;
- `X-Forwarded-For` is accepted only when the socket peer belongs to a configured `MCP_TRUSTED_PROXY_CIDRS` network;
- the trusted forwarded value is normalized before fingerprinting;
- IPv4-mapped IPv6 is normalized back to IPv4;
- invalid values such as `unknown` are rejected from the fingerprint path.

Optional local external-validation event output is configured with:

```bash
export MCP_IDENTITY_TELEMETRY_ENABLED=true
export MCP_IDENTITY_TELEMETRY_TENANT_SALT="<customer-held-salt>"
export MCP_IDENTITY_TELEMETRY_OUTPUT=/var/lib/mcp/identity-telemetry.ndjson
# Optional only when the gateway is behind infrastructure you control:
export MCP_TRUSTED_PROXY_CIDRS="10.0.0.0/8,2001:db8:100::/48"
```

Each NDJSON line is one immutable live transport envelope:

- `schema_version`: integer `1`
- `client`: `mcp-gateway/1.0.0`
- `backfill`: `false`
- `events`: event array
- `event_fps`: positional array with exactly one 32-character lowercase-hex fingerprint per event

The gateway generates a stable logical event ID from the request trace/span context when the queued record is created. The event fingerprint is computed locally as `HMAC-SHA256(key=tenant_salt, message=UTF-8("evt:" + event_id)).hexdigest()[:32]`. The internal event ID is not transmitted.

Raw credentials and raw source addresses are not written to the identity telemetry queue. Token counts are emitted as `0` where MCP-layer token accounting is unavailable. Once queued, the event and its fingerprint are immutable: after an ambiguous transport timeout, retry the exact stored envelope rather than regenerating an ID or changing behavioral fields.

The static field/envelope mapping is complete. A live external baseline is still a separate operational step and is not claimed as completed by this repository.

## Readiness semantics

`/v1/ready` returns 200 only when both forensic persistence directories
(WAL and audit) are writable. A process may be live but not ready.

Do not bypass readiness merely to restore traffic. Repair the durable
persistence path.

## Client integration and availability policy

`GatewayClient` is **fail-closed by default**.

```python
from mcp_monitor.client import GatewayClient

gateway = GatewayClient(
    "http://127.0.0.1:8080",
    api_key="replace-with-production-secret",
)
```

When the gateway is unreachable, the default client blocks tool execution.
Monitoring-only integrations may explicitly choose `fail_closed=False`, but
HTTP 4xx denials remain blocking in every mode.

The wrapper sends tool calls before executing the wrapped function. A blocked
verdict raises `ToolBlocked`.

## Production decision behavior

The production server evaluates the core monitor and then applies:

- approved-server policy;
- detector findings;
- circuit-breaker behavior;
- shadow/enforcement mode;
- audit and WAL persistence;
- optional SIEM event output.

Circuit-breaker fallback for inspection is fail-closed.

`MCP_SHADOW_MODE=true` converts a blocking detector result into an observed
allow decision and must be an explicit operator choice. Production Compose
defaults to enforcement mode.

## Local real-time dashboard

For local visualization only:

```bash
python run_realtime.py
# browser: http://127.0.0.1:8000
```

Synthetic dashboard events require explicit demo mode:

```bash
MCP_DEMO_MODE=1 python run_realtime.py
```

The dashboard/control-plane implementation is not the production deployment
contract and should not be used as evidence that the 8080 enforcement service
is deployed.

## Load testing

The Locust harness requires a configured service credential so it measures the real protected
inspection path rather than 401 responses.

```bash
export MCP_API_KEY="<same configured credential used by the target>"
locust -f locustfile.py --host=http://127.0.0.1:8080 \
  --users 500 --spawn-rate 50
```

The `5000 requests/second` text in the harness is a target scenario, not a
verified production throughput claim. Treat measured results as
hardware/configuration-specific evidence.

## Failure semantics

| Condition | Expected behavior |
|---|---|
| Missing/invalid API key on protected route | 401 |
| Server not in approved set | blocking finding/decision |
| Oversized body | 413 |
| Unsupported transfer encoding / malformed HTTP framing | request rejected |
| Detector exception | fail-closed result |
| Circuit breaker open | fail-closed fallback |
| WAL/audit path unwritable | readiness 503 |
| Shadow mode enabled | detector block is observed but converted to allow |

## Incident evidence

For a suspected bypass or control failure:

1. preserve WAL and audit files;
2. preserve the exact deployed image digest and commit SHA;
3. record the request/call ID and relevant policy configuration;
4. rotate credentials separately from code rollback;
5. compare the observed input against a regression test before changing a rule;
6. do not weaken fail-closed behavior to reduce false positives without a
   documented risk decision.

See `INCIDENT_RUNBOOK.md` for the incident template.

## Evidence boundaries

Repository test counts, coverage percentages, detector counts, and latency
numbers are point-in-time evidence. Do not describe them as current after code
changes unless the exact current commit has a successful reproducible run.

The fixed red-team catalog is a regression suite, not a population-level
real-world detection rate.
