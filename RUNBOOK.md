# Runbook — MCP Security Gateway Monitor v0.1.0

**Last updated:** 2026-08-08  
**Audience:** SREs, AI Platform Engineers, Security Engineers  
**Severity:** This gateway intercepts and inspects MCP tool calls. If it's down, tool calls either bypass inspection (fail-open) or are blocked entirely (fail-closed, depending on your config).

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Installation](#2-installation)
3. [Starting the Gateway Monitor Server](#3-starting-the-gateway-monitor-server)
4. [Configuring Allowed Tools and Servers](#4-configuring-allowed-tools-and-servers)
5. [Integration with MCP Clients](#5-integration-with-mcp-clients)
6. [Monitoring Dashboard Access](#6-monitoring-dashboard-access)
7. [Alert Configuration](#7-alert-configuration)
8. [Injection Detection — Response Procedures](#8-injection-detection--response-procedures)
9. [Tuning Detection Thresholds](#9-tuning-detection-thresholds)
10. [Production Deployment (Docker)](#10-production-deployment-docker)
11. [Troubleshooting](#11-troubleshooting)
12. [Maintenance](#12-maintenance)

---

## 1. Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.10+ | Verify with `python --version` or `py --version` (Windows) |
| pip | Latest | Upgrade: `python -m pip install --upgrade pip` |
| Docker | 20+ | Only for production deployment (port 8080) |
| Docker Compose | v2+ | Only for production deployment |

### Optional Dependencies by Feature

| Feature | Extra | Packages |
|---------|-------|----------|
| Real-time dashboard | `[server]` | FastAPI, uvicorn |
| ML-based detection | `[ml]` | scikit-learn |
| Development/testing | `[dev]` | pytest, pytest-cov, PyYAML, scikit-learn, FastAPI, uvicorn |
| Deep packet inspection | `[dpi]` | mitmproxy |
| ATT&CK mapping | `[attack]` | attack-v19-core |

### Verify Prerequisites

**Windows (PowerShell):**
```powershell
py --version
# Expected: Python 3.10.x or higher

py -m pip --version
# Expected: pip 24.x from ...

docker --version
# Expected: Docker version 24.x or higher (only for production deploy)
```

**Linux / macOS (bash):**
```bash
python3 --version
# Expected: Python 3.10.x or higher

python3 -m pip --version
# Expected: pip 24.x from ...

docker --version
# Expected: Docker version 24.x or higher (only for production deploy)
```

---

## 2. Installation

### Option A: Full Install from Source (Recommended)

**Windows (PowerShell):**
```powershell
git clone https://github.com/poojakira/mcp-security-gateway-monitor.git
cd mcp-security-gateway-monitor
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install --upgrade pip

# Install with all features (dashboard + dev tools)
py -m pip install -e ".[dev,server]"

# Verify installation
py -c "import mcp_monitor; print('OK')"
# Expected: OK
```

**Linux / macOS (bash):**
```bash
git clone https://github.com/poojakira/mcp-security-gateway-monitor.git
cd mcp-security-gateway-monitor
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip

# Install with all features (dashboard + dev tools)
pip install -e ".[dev,server]"

# Verify installation
python3 -c "import mcp_monitor; print('OK')"
# Expected: OK
```

### Option B: Minimal Install (production server only, no dashboard)

**Windows (PowerShell):**
```powershell
git clone https://github.com/poojakira/mcp-security-gateway-monitor.git
cd mcp-security-gateway-monitor
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -e .
```

**Linux / macOS (bash):**
```bash
git clone https://github.com/poojakira/mcp-security-gateway-monitor.git
cd mcp-security-gateway-monitor
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

> **Note:** If PowerShell blocks venv activation, run `Set-ExecutionPolicy -Scope Process Bypass` first.

---

## 3. Starting the Gateway Monitor Server

This project has **two separate services**:

| Service | Port | Purpose | Stack |
|---------|------|---------|-------|
| Real-time control plane | 8000 | Dashboard + `/api/scan` inspection endpoint | FastAPI |
| Production API | 8080 | Docker Compose service with 4-detector monitor | stdlib HTTP |

### Start the Real-time Control Plane (Port 8000)

**Windows (PowerShell):**
```powershell
py -X utf8 run_realtime.py
```

**Linux / macOS (bash):**
```bash
python3 run_realtime.py
```

**Expected output:**
```
INFO:     Started server process
INFO:     Uvicorn running on http://127.0.0.1:8000
INFO:     Application startup complete.
```

**Verify it's running:**

**Windows (PowerShell):**
```powershell
Invoke-RestMethod -Uri http://localhost:8000/api/stats
# Expected: JSON with event counts and detector status
```

**Linux / macOS (bash):**
```bash
curl http://localhost:8000/api/stats
# Expected: JSON with event counts and detector status
```

### Start in Demo Mode (synthetic traffic for testing)

**Windows (PowerShell):**
```powershell
$env:MCP_DEMO_MODE = "1"
py -X utf8 run_realtime.py
```

**Linux / macOS (bash):**
```bash
MCP_DEMO_MODE=1 python3 run_realtime.py
```

Demo events are labeled `demo` in the dashboard. Stop the server and unset the variable when done:

**Windows:** `Remove-Item Env:MCP_DEMO_MODE`  
**Linux/macOS:** `unset MCP_DEMO_MODE`

---

## 4. Configuring Allowed Tools and Servers

### Tool Allow-List

The gateway blocks tool calls that are not in the configured allow-list. Configure via the MCP monitor's policy:

```python
# Example configuration in your integration code
from mcp_monitor.client import GatewayClient

gateway = GatewayClient("http://localhost:8000")

# The gateway inspects every tool call against:
# 1. Allow-listed tool names
# 2. Allow-listed server IDs
# 3. Argument validation rules
# 4. Injection detection patterns
```

### Server Allow-List

Control which MCP servers are permitted to have their tool calls proxied:

```json
{
  "allowed_servers": [
    "postmark",
    "github",
    "slack",
    "internal-db"
  ],
  "blocked_servers": [
    "unknown-*"
  ]
}
```

### Argument Validation

The gateway inspects tool call arguments for:
- **Prompt injection patterns** (e.g., "ignore previous instructions")
- **Data exfiltration attempts** (e.g., encoding secrets in arguments)
- **PII leakage** (e.g., credit card numbers, SSNs in tool arguments)
- **Privilege escalation** (e.g., accessing tools outside the agent's scope)

---

## 5. Integration with MCP Clients

### Claude Desktop Integration

Route Claude Desktop's tool calls through the gateway for inspection:

1. Start the gateway (port 8000):
   ```bash
   python3 run_realtime.py
   ```

2. Configure your MCP client to proxy through the gateway endpoint:
   ```json
   {
     "mcpServers": {
       "security-gateway": {
         "url": "http://localhost:8000/api/scan"
       }
     }
   }
   ```

### Custom MCP Server Integration (Python)

```python
from mcp_monitor.client import GatewayClient, ToolBlocked

# Initialize the gateway client
gateway = GatewayClient("http://localhost:8000")

# Decorate your tool functions with the guard
@gateway.guard
def send_email(*, server_id: str, to: str, body: str) -> str:
    """This function only executes if the gateway allows it."""
    return "sent"

# Usage
try:
    result = send_email(server_id="postmark", to="user@example.com", body="Hello")
    print(f"Success: {result}")
except ToolBlocked as error:
    print(f"BLOCKED: {error.verdict}")
    # Log the blocked call for security review
```

### Fail-Open vs Fail-Closed

By default, `GatewayClient` is **fail-open** on transport errors (gateway unreachable = tool call proceeds). For security-critical deployments:

```python
# Fail-closed: block tool calls if gateway is unreachable
gateway = GatewayClient("http://localhost:8000", fail_closed=True)
```

---

## 6. Monitoring Dashboard Access

### Access the Dashboard

Open in browser: **http://localhost:8000**

API documentation: **http://localhost:8000/docs**

### Dashboard Features

- **Real-time event stream** — tool calls appear as they're inspected
- **Blocking layer identification** — which detector flagged each call
- **Statistics** — total calls, blocked calls, detector hit rates
- **Event history** — searchable log of all inspected calls

### Submitting Test Traffic

**Windows (PowerShell):**
```powershell
$call = @{
  name = "email.send"
  server_id = "postmark"
  arguments = @{
    to = "operator@example.com"
    bcc = "attacker@evil.com"
  }
} | ConvertTo-Json -Depth 4

Invoke-RestMethod -Method Post -Uri http://localhost:8000/api/scan `
  -ContentType "application/json" -Body $call
```

**Linux / macOS (bash):**
```bash
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "name": "email.send",
    "server_id": "postmark",
    "arguments": {"to": "operator@example.com", "bcc": "attacker@evil.com"}
  }'
```

**Expected response (blocked call):**
```json
{
  "allowed": false,
  "verdict": "BLOCKED",
  "detector": "exfiltration",
  "reason": "Suspicious BCC field detected — potential data exfiltration"
}
```

### Check Statistics

**Windows (PowerShell):**
```powershell
Invoke-RestMethod -Uri http://localhost:8000/api/stats
```

**Linux / macOS (bash):**
```bash
curl http://localhost:8000/api/stats
```

---

## 7. Alert Configuration

### Built-in Detection Layers

The gateway runs **4 detection layers** in sequence:

| Layer | Detects | Default Action |
|-------|---------|---------------|
| 1. Allow-list | Tool/server not in approved list | BLOCK |
| 2. Prompt injection | Instruction injection in arguments | BLOCK |
| 3. Data exfiltration | Secrets/PII in outbound arguments | BLOCK |
| 4. Anomaly detection | Unusual call patterns, rate spikes | WARN or BLOCK |

### Configuring Alert Destinations

For production alerting, integrate with your incident management:

```python
# Example: Forward blocked calls to Slack
import requests

def on_blocked(event):
    requests.post(SLACK_WEBHOOK_URL, json={
        "text": f"🚨 MCP tool call BLOCKED\n"
               f"Tool: {event['name']}\n"
               f"Server: {event['server_id']}\n"
               f"Detector: {event['detector']}\n"
               f"Reason: {event['reason']}"
    })
```

### Log-based Alerting

All blocked calls are logged to stdout. Forward to your SIEM:

```bash
# Run with output to log file
python3 run_realtime.py 2>&1 | tee gateway-monitor.log

# Monitor for BLOCKED events
tail -f gateway-monitor.log | grep "BLOCKED"
```

---

## 8. Injection Detection — Response Procedures

### When an Injection Is Detected

**Immediate actions (automated by gateway):**
1. Tool call is **BLOCKED** — it never reaches the target MCP server
2. Event is logged with full payload for forensic analysis
3. Dashboard shows the blocked call with detector identification

**Human response (within 15 minutes):**

1. **Review the blocked call in the dashboard:**
   - Open http://localhost:8000
   - Identify the source (which agent, which session)
   - Check the injection payload

2. **Determine if this is an active attack:**
   - Single blocked call from known agent = likely LLM hallucination or prompt confusion
   - Repeated injection attempts = possible adversarial input to the LLM
   - Injection patterns across multiple tools = **active attack** — escalate immediately

3. **If active attack confirmed:**
   ```bash
   # Kill the agent session if possible
   # Block the source at the network level
   # Preserve logs for forensics
   cp gateway-monitor.log "incident-$(date +%s).log"
   ```

4. **Trace the injection source:**
   - What user input triggered the agent?
   - Was the injection in a document the agent read?
   - Was the injection in a tool response (indirect prompt injection)?

5. **Notify security team:**
   - Post to `#security-incidents` with:
     - Injection payload (sanitized)
     - Source identification
     - Whether any calls succeeded before detection
     - Impact assessment

### Escalation Matrix

| Scenario | Action | SLA |
|----------|--------|-----|
| Single blocked injection | Log and monitor | Review within 4 hours |
| Repeated injections from one source | Block source, investigate | 1 hour |
| Injection in tool response (indirect) | Alert upstream service owner | 30 minutes |
| Successful bypass detected | SEV-1 incident, full containment | 15 minutes |

---

## 9. Tuning Detection Thresholds

### Detection Sensitivity

The 4 detection layers can be tuned independently:

### Layer 2: Prompt Injection Detection

Common tuning scenarios:

| Scenario | Adjustment |
|----------|------------|
| Too many false positives from code snippets | Add code-pattern exceptions |
| Missing injections with unicode obfuscation | Enable unicode normalization |
| Legitimate "ignore" instructions blocked | Whitelist specific tool+argument patterns |

### Layer 3: Exfiltration Detection

| Scenario | Adjustment |
|----------|------------|
| Base64-encoded arguments triggering alerts | Set minimum entropy threshold higher |
| Short strings triggering PII detection | Increase minimum token length |
| Known API keys being flagged | Add to known-safe patterns list |

### Layer 4: Anomaly Detection

| Scenario | Adjustment |
|----------|------------|
| Burst of legitimate calls triggering rate limit | Increase rate threshold |
| New tool added but being blocked | Add to allow-list first |
| Seasonal traffic patterns causing alerts | Adjust baseline window |

### Benchmarking After Changes

After tuning, validate detection still works:

**Windows (PowerShell):**
```powershell
py -m pytest tests/test_5_layers.py tests/test_prompt_injection.py tests/test_exfiltration.py -q --tb=short
```

**Linux / macOS (bash):**
```bash
pytest tests/test_5_layers.py tests/test_prompt_injection.py tests/test_exfiltration.py -q --tb=short
```

**Expected:** All tests pass. If detection tests fail after tuning, you've weakened security.

### Latency Benchmarking

Ensure tuning didn't degrade performance:

**Windows (PowerShell):**
```powershell
py benchmark/tool_call_latency.py --iterations 200
# Expected: p99 < 50ms per tool call inspection
```

**Linux / macOS (bash):**
```bash
python3 benchmark/tool_call_latency.py --iterations 200
# Expected: p99 < 50ms per tool call inspection
```

---

## 10. Production Deployment (Docker)

### Setup

1. **Create the environment file:**

**Windows (PowerShell):**
```powershell
Copy-Item .env.example .env
notepad .env
# Set: MCP_API_KEY=<generate a long random value>
```

**Linux / macOS (bash):**
```bash
cp .env.example .env
# Edit .env and set: MCP_API_KEY=<generate a long random value>
nano .env
```

2. **Set the API key in shell (for Docker Compose):**

**Windows (PowerShell):**
```powershell
$env:MCP_API_KEY = "your-long-random-value-here"
```

**Linux / macOS (bash):**
```bash
export MCP_API_KEY="your-long-random-value-here"
```

3. **Start the production service:**

```bash
docker compose up --build -d
```

4. **Verify health:**

**Windows (PowerShell):**
```powershell
Invoke-RestMethod -Uri http://localhost:8080/v1/health
# Expected: {"status": "healthy"}
```

**Linux / macOS (bash):**
```bash
curl http://localhost:8080/v1/health
# Expected: {"status": "healthy"}
```

### Production Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/health` | GET | Health check |
| `/v1/scan` | POST | Submit tool call for inspection |
| `/v1/stats` | GET | Runtime statistics |

### Load Testing

```bash
pip install locust==2.31.8
locust -f locustfile.py --host=http://localhost:8080
# Open http://localhost:8089 for Locust web UI
```

---

## 11. Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| `ModuleNotFoundError: fastapi` | Server extras not installed | `pip install -e ".[dev,server]"` |
| Can't reach port 8000 | Port occupied by another process | **Windows:** `Get-NetTCPConnection -LocalPort 8000` then kill. **Linux:** `lsof -i :8000` then `kill <PID>` |
| Dashboard is empty after start | Normal — no traffic yet | Send a `POST /api/scan` call, or set `MCP_DEMO_MODE=1` |
| Docker Compose exits immediately | `MCP_API_KEY` not set | Set it in `.env` file AND as shell variable |
| Console garbled characters | Unicode encoding issue | Start with `py -X utf8 run_realtime.py` (Windows) |
| `ConnectionRefusedError` from client | Gateway not running | Start `run_realtime.py` first, verify with `curl http://localhost:8000/api/stats` |
| Tool calls succeeding despite gateway | Client is fail-open + gateway down | Either fix gateway, or set `fail_closed=True` on client |
| High latency on tool calls | ML detector enabled but model cold | First call warms up the model. Subsequent calls should be <50ms. |
| Tests failing after tuning | Detection weakened | Revert threshold changes and re-run tests |
| `PermissionError` on port 8000 | Linux: ports <1024 need root | Use port 8000 (default), or run with elevated privileges |
| Docker build fails | Missing .env file | `cp .env.example .env` and set `MCP_API_KEY` |

---

## 12. Maintenance

### Pre-Change Validation

Run these **before** making any changes or giving a demo:

**Windows (PowerShell):**
```powershell
py -m ruff format --check src tests run_realtime.py
py -m ruff check src tests run_realtime.py
py -m pytest tests/test_5_layers.py tests/test_cross_platform.py tests/test_realtime.py -q --tb=short
py benchmark/tool_call_latency.py --iterations 200
```

**Linux / macOS (bash):**
```bash
ruff format --check src tests run_realtime.py
ruff check src tests run_realtime.py
pytest tests/test_5_layers.py tests/test_cross_platform.py tests/test_realtime.py -q --tb=short
python3 benchmark/tool_call_latency.py --iterations 200
```

### Full Test Suite

**Windows (PowerShell):**
```powershell
py -m pytest tests/ -q --tb=short
```

**Linux / macOS (bash):**
```bash
pytest tests/ -q --tb=short
```

### Updating

```bash
cd mcp-security-gateway-monitor
git pull origin main
pip install -e ".[dev,server]"
pytest tests/ -q --tb=short
```

### Shutdown

- `Ctrl+C` in the server terminal
- Don't commit: `security_dashboard.html`, benchmark output, `.venv`, `.env`, API keys
- Keep audit/WAL data per your organization's retention policy

### Version Upgrades

1. Read CHANGELOG.md for breaking changes
2. Run full test suite after upgrade
3. Re-run latency benchmark to catch regressions
4. Verify detection rates haven't changed: `pytest tests/test_5_layers.py -v`

---

## Quick Reference Card

```bash
# Start real-time dashboard (port 8000)
python3 run_realtime.py

# Start in demo mode
MCP_DEMO_MODE=1 python3 run_realtime.py

# Submit a tool call for inspection
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"name": "tool.name", "server_id": "server", "arguments": {}}'

# Check stats
curl http://localhost:8000/api/stats

# Start production service (Docker)
docker compose up --build -d

# Health check (production)
curl http://localhost:8080/v1/health

# Run tests
pytest tests/ -q --tb=short

# Benchmark latency
python3 benchmark/tool_call_latency.py --iterations 200
```

---

## Architecture Notes

> **IMPORTANT:** This is a prototype with 51% detection rate. It demonstrates the architecture for MCP security monitoring but is NOT production-hardened. For production use, evaluate detection accuracy against your threat model and supplement with additional controls.
