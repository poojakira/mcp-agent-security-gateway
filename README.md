# MCP Agent Security Gateway

**Repository owner & maintainer:** Pooja Kiran ([@poojakira](https://github.com/poojakira)) — I own and maintain this repository and drive its design, engineering, validation, documentation, and evidence-backed releases.

Security controls for MCP/JSON-RPC tool calls at the agent-to-tool boundary.

## Threat model

This project assumes an AI agent may produce unsafe or manipulated tool calls even when the underlying model and MCP server are otherwise functioning correctly. The gateway focuses on risks such as prompt-injection content in tool arguments, unexpected server/capability use, sensitive-data leakage, suspicious process-execution intent, and disallowed egress destinations.

It is **not** an OS firewall, endpoint agent, or complete DLP system. Only traffic routed through the gateway can be inspected or blocked.

See [THREAT_MODEL.md](THREAT_MODEL.md) for the full model and residual risks.

## Quick start

```bash
git clone https://github.com/poojakira/mcp-agent-security-gateway.git
cd mcp-agent-security-gateway
python -m venv .venv
source .venv/bin/activate   # Windows: .\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev,server]"
python -m pytest tests -q
```

Run a downstream stdio MCP server through the proxy:

```bash
python -m mcp_monitor.proxy.stdio_proxy -- <server-command> [args...]
```

The stdio proxy rejects malformed or duplicate-key JSON before forwarding.
It inspects every `tools/call` in a JSON-RPC batch and rejects the whole batch
if any call is blocked. Notifications are forwarded without waiting for a
response; blocked notifications receive no response. These checks apply to
traffic routed through this stdio proxy.

Run the local FastAPI control plane:

```bash
python run_realtime.py
```

Default local endpoints include `/`, `/docs`, `/api/scan`, `/api/stats`, and `/ws` on `127.0.0.1:8000`.

## What is implemented

- Inline MCP stdio proxy for selected `tools/call` requests
- JSON-RPC parsing and request validation
- Prompt-injection-oriented argument inspection with normalization
- Server-registry and capability checks
- PII/sensitive-data and exfiltration signals
- Application-level process-execution and egress-policy decisions
- Hash-chained audit logging and write-ahead logging
- Rate limiting, tracing, metrics, circuit-breaker components, and shadow mode
- ECS-formatted security events plus a local Elastic detection lab
- Docker and Kubernetes deployment templates

These capabilities are split across multiple runtime paths. The inline stdio proxy, FastAPI control plane, and HTTP inspection surfaces do not provide identical enforcement behavior; integration-specific limits are documented in the runbooks and source.

## Verified evidence

Historical main CI evidence and local verification: [VERIFIED_METRICS.md](VERIFIED_METRICS.md)

| Claim | Verified value | Scope |
|---|---:|---|
| Automated tests | **648 passed locally** | Current checkout, Python 3.12; CI pending |
| Statement coverage | **79.61% locally** | Current checkout, Python 3.12; CI pending |
| Prompt-injection regex patterns | **55** | Compiled entries in the detector |
| Elastic Security rules | **9** | Committed rule definitions |
| Core SIEM tests | **21** | `tests/test_siem.py` |

The cited historical CI run includes Ruff, Pyright, Bandit, pip-audit, CodeQL, Trivy, Grype, SBOM generation, Docker build validation, and Python 3.10/3.11/3.12 test jobs. These gates have not yet run against the local repair commit.

Historical application-time metrics are preserved separately in [docs/evidence/RESUME_EVIDENCE.md](docs/evidence/RESUME_EVIDENCE.md).

## Architecture

```text
Agent / MCP client
       |
       v
Inline stdio proxy or HTTP control plane
       |
       +--> parse / normalize
       +--> trust + capability checks
       +--> content / policy signals
       +--> audit + telemetry
       |
       v
allow / block decision
       |
       v
downstream MCP server or integrating application
```

Enforcement depends on the integration path. For example, the Python wrapper raises `ToolBlocked` when the control plane returns `allowed=false`; transport failures are surfaced to the caller rather than silently converted into an allow/deny decision.

## Detection lab

The optional local detection lab converts gateway security events to ECS, evaluates correlation logic, and includes ATT&CK-mapped Elastic rule definitions and attack-simulation fixtures. It is a development/validation environment, not evidence of production SOC deployment.

See [detection_lab/README.md](detection_lab/README.md).

## Performance claims

No production latency or throughput guarantee is made in this README. Benchmark scripts and environment-scoped baselines live under `benchmark/`, `benchmarks/`, and [docs/PERFORMANCE_BASELINE.md](docs/PERFORMANCE_BASELINE.md). Treat those values as reproducible benchmark evidence for the documented environment, not deployment SLOs.

## Security and contribution guidance

- [SECURITY.md](SECURITY.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [INCIDENT_RUNBOOK.md](INCIDENT_RUNBOOK.md)
- [RUNBOOK.md](RUNBOOK.md)
- [THREAT_MODEL.md](THREAT_MODEL.md)

## Reproducing the main checks

```bash
python -m pytest tests -q --cov=src/mcp_monitor
ruff check src tests
ruff format --check src tests
bandit -r src -ll
pip-audit
```

GitHub Actions is the authoritative environment for the repository's current published test/coverage claims.

## License

MIT — see [LICENSE](LICENSE).
