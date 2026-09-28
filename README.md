<!-- security-systems-poster -->
## Research Poster

**Security Systems / 01 ΓÇö Runtime Policy Enforcement at the AI Agent-to-Tool Boundary**

[![Research poster](poster/poster.png)](poster/poster_36x48.pdf)

> Technical research poster (36 x 48 in). Click the image for the print-resolution **[PDF](poster/poster_36x48.pdf)**.
> Every metric on it is evidence-backed; historical/projected numbers are labeled and separated from current results.
<!-- security-systems-poster -->

# MCP Agent Security Gateway

> Inspect and enforce AI-agent MCP/JSON-RPC tool calls at the agent-to-tool boundary before they execute.

[![CI](https://github.com/poojakira/mcp-agent-security-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/poojakira/mcp-agent-security-gateway/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-659%20passing-brightgreen)](VERIFIED_METRICS.md)
[![Coverage](https://img.shields.io/badge/coverage-82%25-brightgreen)](VERIFIED_METRICS.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Maintainer: Pooja Kiran ([@poojakira](https://github.com/poojakira)).

## Overview

`mcp-agent-security-gateway` sits between an AI agent (MCP client) and downstream MCP servers and inspects each `tools/call` request over JSON-RPC before it executes, returning an allow/block decision. It applies prompt-injection, PII/exfiltration, capability/shadow-server, and process/egress-policy checks, and records tamper-evident audit and telemetry. It exists because an agent that can call tools, assume roles, and load artifacts is making privileged decisions on infrastructure, and nothing in the base MCP protocol inspects those calls. Enforcement applies only to traffic routed through a supported integration path ΓÇö this is a production-oriented research prototype, not a network firewall or a deployed SOC.

## Verified Snapshot

Reproduced on current `main` (Python 3.12); also green in GitHub Actions. Evidence: [VERIFIED_METRICS.md](VERIFIED_METRICS.md).

| Metric | Current verified result |
|---|---:|
| Tests | 659 passing |
| Statement coverage | 82% |
| Prompt-injection patterns | 55 (`INJECTION_PATTERNS`) |
| Elastic Security rules | 9 |
| Core SIEM tests | 21 |

## Security Problem

MCP gives agents a standardized way to invoke external tools that can read data, send messages, reach networks, or execute operations. That creates a trust boundary between model-generated requests and systems that can act. The gateway addresses whether a caller can apply explicit validation, authorization, detection, audit, and policy controls before selected tool calls reach a downstream server ΓÇö covering prompt-injection content in arguments, unexpected server/capability use, sensitive-data leakage, process-execution intent, and disallowed egress destinations.

## Threat Model & Scope

Adversaries modeled: malicious prompt authors, compromised MCP servers, rogue agents, and insiders with log access. See [THREAT_MODEL.md](THREAT_MODEL.md) for the full model and residual risks.

**In scope:** JSON-RPC traffic routed through the gateway (stdio proxy or the HTTP control plane); heuristic detection; tamper-evident audit.

**Out of scope / not claimed:** It is not an OS firewall, endpoint agent, or complete DLP system. Its egress control is application-layer policy, not packet-level enforcement. Detectors are heuristic (false positives and negatives possible). Enforcement depends on the integration path; only routed traffic can be inspected or blocked.

## Architecture

```text
Agent / MCP client
       |
       v
Inline stdio proxy  OR  HTTP control plane (/v1/inspect_call)
       |
       +--> parse / normalize (JSON-RPC 2.0)
       +--> capability + shadow-server checks
       +--> content / policy signals (injection, PII, exfiltration, egress)
       +--> audit (hash-chained) + WAL + telemetry
       |
       v
allow / block decision  (fail-closed on detector/circuit-breaker error)
       |
       v
downstream MCP server or integrating application
```

Enforcement depends on the integration path: the Python wrapper raises `ToolBlocked` when the control plane returns `allowed=false`; the stdio proxy rejects malformed/duplicate-key JSON and blocks disallowed batched calls.

## Core Capabilities

- Inline MCP stdio proxy for selected `tools/call` requests
- JSON-RPC 2.0 parsing and request validation
- Prompt-injection-oriented argument inspection with normalization (55 patterns)
- Server-registry and capability (shadow-server) checks
- PII/sensitive-data and exfiltration signals
- Application-level process-execution and egress-policy decisions
- Hash-chained audit logging and write-ahead logging
- Rate limiting, tracing, metrics, circuit breaker (fail-closed), shadow mode
- ECS-formatted security events plus a local Elastic detection lab (9 rules)
- Docker and Kubernetes deployment templates

## Recent verified additions

These follow the same discipline as the rest of the repo: separate detection from enforcement, attach scope to every metric, and label anything synthetic or unverified. They are additive modules with their own verified test counts and do not change the repository-wide test/coverage snapshot above.

### Policy-as-code PDP (enforcement)

`src/mcp_monitor/policy/policy_engine.py` is a fail-closed, default-deny Python Policy Decision Point: deny-wins evaluation, structured reason codes, and anti-SSRF egress checks. Enforcement is proven, not asserted — `tests/test_policy_enforcement.py` is **15 passed** (verified locally with `.venv`, Ruff clean), including tests that a denied tool call **never reaches the downstream transport** (`send`/`receive` not called) and that allowed calls do. Rego policies under `policy/rego/` exist for OPA parity but are **UNVERIFIED here — requires the `opa` binary**. See [docs/policy/POLICY_AS_CODE.md](docs/policy/POLICY_AS_CODE.md).

### Detection-engineering lifecycle

`src/mcp_monitor/siem/lifecycle.py` generates a coverage matrix (6 correlation rules + 9 Elastic rules mapped to 7 ATT&CK techniques, with ATLAS cross-references) plus per-rule precision/recall. The precision/recall numbers are computed on **synthetic fixtures only**: micro-averaged P/R/F1 = **1.000** over **9 fixture sequences** — this measures fixture coverage, **not real-world efficacy**. A local latency microbench over **2000 synthetic events** records **p50 0.47ms, p95 1.19ms, p99 1.75ms (~1863 events/s single-process)** — a **local microbench, not a production SLA**. Artifacts in [docs/detection/](docs/detection/); tuning log in [docs/detection/TUNING_LOG.md](docs/detection/TUNING_LOG.md); tests in `tests/test_detection_lifecycle.py`.

### Native inspection cores (Rust + C++)

The `rust/` crate ports the fail-closed JSON-RPC inspection decision (parse, duplicate-key rejection, batch atomicity, allow/block/indeterminate) to Rust. Verified via a `rust:1-slim` Docker build: `cargo build` **0 warnings**, `cargo test` **9 passed / 0 failed**. See [rust/README.md](rust/README.md).

The `cpp/` directory ports the same fail-closed inspection core to C++17, with a small self-contained JSON parser that explicitly rejects duplicate keys. Verified via a `gcc:13` Docker build: compiled with `-Wall -Wextra -Wpedantic` (no warnings), `make test` **11/11 checks passed**, and the CMake path reports `ctest` **100% passed (1/1)**. Both native cores hold the same parity table as the Python implementation. See [cpp/README.md](cpp/README.md).

## Installation

```bash
git clone https://github.com/poojakira/mcp-agent-security-gateway.git
cd mcp-agent-security-gateway
python -m venv .venv
source .venv/bin/activate   # Windows: .\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev,server]"
python -m pytest tests -q
```

## Usage

Run a downstream stdio MCP server through the proxy:

```bash
python -m mcp_monitor.proxy.stdio_proxy -- <server-command> [args...]
```

Run the local FastAPI control plane (default `127.0.0.1:8000`):

```bash
python run_realtime.py
```

Production API (port 8080) requires `X-API-Key` on inspection/metrics endpoints; `/v1/health` and `/v1/ready` are open for orchestration. See [RUNBOOK.md](RUNBOOK.md).

## Testing

```bash
python -m pytest tests -q --cov=mcp_monitor
ruff check src tests
ruff format --check src tests
bandit -r src -ll
pip-audit
```

Current verified: **659 passing, 82% statement coverage**. GitHub Actions is the authoritative environment for published test/coverage claims.

## CI/CD

GitHub Actions runs Ruff, Pyright, Bandit, pip-audit, CodeQL, Trivy, SBOM generation, Docker build validation, and the Python 3.10/3.11/3.12 test matrix plus a Windows control-plane job. These gates pass on the current `main` commit.

## Security & Documentation

- [SECURITY.md](SECURITY.md) ┬╖ [THREAT_MODEL.md](THREAT_MODEL.md) ┬╖ [SECURITY_AUDIT.md](SECURITY_AUDIT.md)
- [RUNBOOK.md](RUNBOOK.md) ┬╖ [INCIDENT_RUNBOOK.md](INCIDENT_RUNBOOK.md) ┬╖ [PRODUCTION.md](PRODUCTION.md)
- [VERIFIED_METRICS.md](VERIFIED_METRICS.md) ┬╖ [RESEARCH_REPORT.md](RESEARCH_REPORT.md)
- Detection lab: [detection_lab/README.md](detection_lab/README.md)
- Performance baselines: [docs/PERFORMANCE_BASELINE.md](docs/PERFORMANCE_BASELINE.md)

## Limitations

Heuristic detectors can be evaded; the fixed red-team catalog is a regression suite, not a population-level detection rate. No production latency/throughput/uptime guarantee is made. Enforcement is only as strong as the integration path routing traffic through the gateway.

## Project Status

**Production-oriented research prototype.** Functional, tested, and CI-validated, with fail-closed auth and tamper-evident audit ΓÇö but not proven at production scale or in a live SOC deployment.

## License

MIT ΓÇö see [LICENSE](LICENSE).
