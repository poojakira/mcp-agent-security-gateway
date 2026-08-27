# Threat Model — MCP Agent Security Gateway

This document describes the threat model for the MCP Agent Security Gateway. It identifies the adversaries, attack surfaces, trust boundaries, and mitigations implemented.

---

## Adversary Model

| Adversary | Capability | Goal |
|---|---|---|
| Malicious prompt author | Crafts inputs that manipulate agent behavior | Cause the agent to invoke tools in unintended ways |
| Compromised MCP server | Returns poisoned tool outputs or altered schemas | Exfiltrate data, escalate capability, or inject instructions |
| Rogue agent | Autonomous agent operating outside intended boundaries | Access unauthorized tools, exfiltrate data, spawn processes |
| Network attacker | Can intercept or inject traffic between components | Man-in-the-middle tool calls, steal credentials |
| Insider with log access | Has access to audit logs | Tamper with evidence of security decisions |

---

## Trust Boundaries

```text
┌─────────────────────────────────────────────────────┐
│                  Untrusted Zone                       │
│                                                      │
│  User Prompts · Agent Decisions · Tool Arguments     │
│  Tool Outputs · External MCP Servers                 │
│                                                      │
└───────────────────────┬─────────────────────────────┘
                        │
              ┌─────────▼─────────┐
              │  Security Gateway  │  ← Trust boundary
              └─────────┬─────────┘
                        │
┌───────────────────────▼─────────────────────────────┐
│                  Trusted Zone                         │
│                                                      │
│  Policy Engine · Audit Log · Configuration           │
│  Rate Limiter · Circuit Breaker State                │
│                                                      │
└─────────────────────────────────────────────────────┘
```

---

## Attack Surfaces

### 1. Tool-Call Arguments (Prompt Injection)

**Threat**: Adversary embeds instructions in tool arguments that manipulate downstream behavior or bypass security controls.

**Mitigations**:
- 50+ prompt-injection detection rules
- Unicode normalization (zero-width removal, homoglyph handling, BiDi control stripping)
- Base64/ROT13 decoding attempts before inspection
- Multi-layer policy evaluation

### 2. MCP Server Identity Spoofing

**Threat**: Agent invokes a tool on an unregistered or impersonated MCP server.

**Mitigations**:
- Server registry with allow-list
- Capability boundary checks per server
- Unregistered server rejection at Layer 1

### 3. Data Exfiltration via Tool Calls

**Threat**: Agent sends sensitive data to external destinations through tool arguments.

**Mitigations**:
- PII detection (SSN, credit card, API keys, etc.)
- Exfiltration indicator checks (hidden recipients, oversized payloads, raw-IP destinations)
- Network egress policy engine
- Tool-output inspection (bidirectional boundary)

### 4. Process Execution via Tool Arguments

**Threat**: Tool arguments contain shell commands or process-spawn indicators.

**Mitigations**:
- Layer 3 process-spawn intent evaluation
- Pattern detection for subprocess, os.system, shell invocations
- Security invariants for destructive operations

### 5. Circuit Breaker Bypass

**Threat**: Attacker floods detectors to trigger circuit breaker, then sends malicious requests while detectors are unavailable.

**Mitigations**:
- Circuit breaker fallback produces DENY (fail-closed on this specific path)
- Rate limiting on inspection endpoints
- Separate circuit breakers for call and output inspection

### 6. Audit Log Tampering

**Threat**: Attacker modifies historical audit entries to hide evidence of blocked or suspicious requests.

**Mitigations**:
- SHA-256 hash-chained audit log
- Write-ahead logging with request-body hashes
- Tamper-evident verification (chain integrity checks)

### 7. API Key Compromise

**Threat**: Attacker obtains the gateway API key and submits unauthorized inspection requests.

**Mitigations**:
- API key required on protected endpoints by default
- Anonymous mode requires explicit opt-in
- Rate limiting bounds abuse potential

### 8. Tool Schema Drift

**Threat**: MCP server silently changes tool definitions to expand capabilities or alter parameters.

**Mitigations**:
- Tool manifest integrity checking
- Behavioral drift detection
- Canary validation probes

---

## Failure Modes

| Component | Failure Mode | Security Impact | Mitigation |
|---|---|---|---|
| Detector | Unavailable | Requests uninspected | Circuit breaker → DENY |
| Policy engine | Unavailable | No policy decision | Circuit breaker → DENY |
| Audit logger | Unavailable | Audit gap | Inspection continues, gap logged |
| Downstream MCP server | Crash | Connection error | Error propagates to caller |
| Rate limiter | Exhausted | Requests rejected | Operational endpoints exempt |
| Configuration | Missing API key | Auth bypass risk | Protected requests rejected (401) |

---

## Scope Limitations

1. **Not a network firewall**: Egress policy returns decisions but does not intercept packets.
2. **Not an OS-level sandbox**: Process-event evaluation requires externally supplied events.
3. **Not a complete DLP solution**: PII detection is heuristic, not exhaustive.
4. **Detection is heuristic**: False positives and false negatives are possible.
5. **Enforcement is external**: The integrating runtime must honor returned decisions.
6. **Single-process trust**: The gateway trusts its own process memory and configuration.

---

## Related Documents

- [`SECURITY.md`](SECURITY.md) — Security policy and vulnerability reporting
- [`SECURITY_AUDIT.md`](SECURITY_AUDIT.md) — Security review and validation notes
- [`README.md`](README.md) — Architecture, failure semantics, and operational guidance
