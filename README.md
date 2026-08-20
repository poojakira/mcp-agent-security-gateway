# MCP Agent Security Gateway

Stdio proxy that intercepts MCP `tools/call` JSON-RPC messages and runs them through a multi-layer security pipeline. Returns Allow / Block / Redact verdicts.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![CI](https://github.com/poojakira/mcp-agent-security-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/poojakira/mcp-agent-security-gateway/actions/workflows/ci.yml)

## What This Does

Sits between an MCP agent and tool server, inspects every `tools/call` request, and makes a security decision before anything reaches the downstream server. No code changes required on either side.

Detection layers:
1. **Server trust** — allowlist check on target server identity
2. **Tool-call policy** — per-tool allow/deny rules, argument schema validation
3. **Process-spawn evaluation** — blocks shell commands in arguments
4. **Semantic analysis** — prompt-injection patterns, PII detection, unicode normalization
5. **Egress control** — domain allowlisting, data volume thresholds

## Status

This is a working prototype, not production software. It handles the common cases well but has known gaps:
- Detection is regex/pattern-based — no ML classifier, so novel attacks will bypass it
- Latency numbers are from synthetic benchmarks, not real MCP workloads
- No async support yet
- Test suite covers happy paths thoroughly; adversarial edge cases less so

## Install

```bash
git clone https://github.com/poojakira/mcp-agent-security-gateway.git
cd mcp-agent-security-gateway
pip install -e ".[dev]"
```

## Run Tests

```bash
pytest tests/ -v
```

## Usage

```python
from mcp_monitor.monitor import MCPSecurityMonitor
from mcp_monitor.audit.log import AuditLog

audit = AuditLog()
monitor = MCPSecurityMonitor(
    allowed_servers={"weather-server", "db-server"},
    audit_log=audit,
)

result = monitor.inspect_call({
    "name": "query_db",
    "server_id": "db-server",
    "arguments": {"sql": "SELECT * FROM users"},
})
print(result)  # {"allowed": True, "risk_score": 0, ...}
```

## Architecture

```
MCP Agent → [stdio] → Security Gateway → [stdio] → MCP Tool Server
                            │
                     5-layer pipeline
                     SHA-256 audit log
```

Each layer can independently block. Decisions are logged to a hash-chained audit trail.

## What It Detects

- Prompt injection patterns (50+ regex rules)
- PII in tool arguments (SSN, credit card, email, phone, AWS keys, JWT)
- Shadow/unauthorized MCP servers
- Data exfiltration via tool arguments
- Process spawn attempts in arguments
- Unicode homoglyph attacks

## CI

Runs on every push: Ruff lint, Pyright type checking, pytest with coverage, Bandit SAST, Trivy/Grype vulnerability scanning, CodeQL.

## Contributing

Open an issue first. Run `ruff check src/ tests/` and `pytest` before submitting PRs.

## License

MIT
