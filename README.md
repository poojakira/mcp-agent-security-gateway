# MCP Agent Security Gateway

Security controls for MCP/JSON-RPC tool calls at the agent-to-tool boundary.

The gateway inspects requests that are explicitly routed through it. It is **not** a network firewall, OS sandbox, or universal prompt-injection defense. Heuristic detectors can produce false positives and false negatives, and downstream runtimes must honor the gateway's allow/deny decision.

## Threat model first

Primary threats addressed:

- prompt injection embedded in tool arguments
- unregistered or capability-incompatible MCP servers
- sensitive-data exfiltration attempts
- suspicious process-execution intent
- tool-schema drift and server impersonation
- audit-log tampering
- abuse bursts against inspection endpoints

See [THREAT_MODEL.md](THREAT_MODEL.md) for adversaries, trust boundaries, failure modes, and scope limitations.

## Quick start

Requires Python 3.10+.

```bash
git clone https://github.com/poojakira/mcp-agent-security-gateway.git
cd mcp-agent-security-gateway
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
pip install -e ".[server]"
export MCP_API_KEY="replace-with-a-long-random-value"
mcp-gateway
```

For development and tests:

```bash
pip install -e ".[dev]"
python -m pytest tests/ -q
```

## Architecture

```text
Agent / client
     |
     v
MCP / JSON-RPC inspection boundary
     |
     +--> server registry + capability checks
     +--> prompt-injection / PII / exfiltration signals
     +--> policy + invariant evaluation
     +--> rate limiting / circuit-breaker paths
     +--> hash-chained audit logging
     |
     v
Allowed downstream MCP server
```

The repository also contains an optional FastAPI service, stdio proxy, SIEM/Elastic lab, Docker/Kubernetes examples, and red-team regression tooling. Operational detail lives in the linked docs rather than this README.

## Verified repository facts

Current CI evidence from the successful Python 3.12 job on 2026-09-21:

| Claim | Verified value |
|---|---:|
| Tests | **629 passed** |
| Statement coverage | **78.47%** |
| Python CI matrix | **3.10 / 3.11 / 3.12** |
| Elastic Security rules | **9** |
| Core SIEM tests | **21** |

The test and coverage values are taken from GitHub Actions, not inferred from README text. Static rule counts are documented in [VERIFIED_METRICS.md](VERIFIED_METRICS.md).

Historical resume/application evidence is intentionally separated from current metrics in [docs/evidence/RESUME_EVIDENCE.md](docs/evidence/RESUME_EVIDENCE.md). The earlier **622 tests / 78%** snapshot remains traceable to its cited CI run.

## What this project does not claim

- The bundled 37/37 red-team catalog result is a fixed regression self-test, **not** a real-world detection rate.
- Egress policy decisions do not independently intercept arbitrary network packets.
- Process-event evaluation is not an OS-level sandbox.
- PII and prompt-injection detection are heuristic.
- The repository does not claim universal MCP security or production effectiveness outside the tested paths.

## Important entry points

- `src/mcp_monitor/proxy/stdio_proxy.py` — inline stdio MCP proxy
- `src/mcp_monitor/production/server.py` — optional HTTP service
- `src/mcp_monitor/protocol/jsonrpc.py` — JSON-RPC parsing and validation
- `src/mcp_monitor/detectors/prompt_injection.py` — prompt-injection rules
- `src/mcp_monitor/audit.py` — audit chain
- `tests/` — security and regression tests
- `.github/workflows/ci.yml` — CI, security scanning, type checks, Docker build

## Documentation

- [Threat model](THREAT_MODEL.md)
- [Security policy](SECURITY.md)
- [Security audit notes](SECURITY_AUDIT.md)
- [Runbook](RUNBOOK.md)
- [Incident runbook](INCIDENT_RUNBOOK.md)
- [Detection lab](detection_lab/README.md)
- [Performance baseline](docs/PERFORMANCE_BASELINE.md)
- [Verified metrics](VERIFIED_METRICS.md)
- [Resume evidence](docs/evidence/RESUME_EVIDENCE.md)
- [Contributing](CONTRIBUTING.md)

## Security reporting

Please follow [SECURITY.md](SECURITY.md). Do not open a public issue for a vulnerability that could put users at risk.

## License

See [LICENSE](LICENSE).
