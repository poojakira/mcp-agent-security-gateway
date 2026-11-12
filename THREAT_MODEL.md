> **Evidence reconciliation (2026-11-11; living reference):** Historical results below retain their original dates and denominators. Latest tested Phase 1–16 development SHA is `43a72c8984bf9a472b9055d4f9e84cc759f61718` ([CI](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42971171992): 1,211 passed, 6 skipped per Python version), **not** a merged or production-approved release. Offline research tests require no paid provider or provider-issued API keys; deployed HTTP authentication and unverified real credential revocation remain separate. See [operating restrictions](PRODUCTION.md) and [release evidence](docs/review/PHASE1_16_RELEASE_CANDIDATE_NO_GO_20261110.md).

# Threat Model — MCP Agent Security Gateway

This document records attack assumptions, implemented controls and unresolved security properties across multiple research and gateway integration paths. **Production status: NO-GO**; controls differ by entry point, and a passing local test is not proof of non-bypassable deployment. See [release gate](docs/review/PHASE13_RELEASE_READINESS.md).

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
- Pattern-based prompt-injection inspection (the October 14 poster source snapshot inventories **69 named signatures**; verify the collection on the exact branch/commit under review). Signature count is not a measurement of recall or bypass resistance.
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
- Application-layer network destination policy signals (not packet-level outbound enforcement)
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
- Circuit breaker fallback produces DENY in the specifically tested inspection path; do not generalize to every adapter
- Rate limiting on inspection endpoints
- Separate circuit breakers for call and output inspection

### 6. Audit Log Tampering

**Threat**: Attacker modifies historical audit entries to hide evidence of blocked or suspicious requests.

**Mitigations**:
- SHA-256 hash-chained audit log
- Write-ahead logging with request-body hashes
- Tamper-evident verification (chain integrity checks)

### 7. API Credential Compromise

**Threat**: Attacker obtains one configured gateway credential and submits unauthorized inspection requests.

**Mitigations**:
- API credential required on protected HTTP endpoints by default; other adapters require separate identity/routing review
- Legacy single-key and stable multi-key configurations are supported; compromised credentials can be rotated independently of code
- Anonymous mode requires explicit opt-in
- Rate limiting bounds abuse potential
- Privacy-preserving telemetry fingerprints the credential locally instead of exporting the raw value

### 8. Source-Address Spoofing Behind Proxies

**Threat**: A client supplies a forged forwarded-source header so identity/network telemetry attributes requests to an attacker-selected address.

**Mitigations**:
- Socket peer address is authoritative by default
- `X-Forwarded-For` is consulted only when the socket peer belongs to an explicitly configured `MCP_TRUSTED_PROXY_CIDRS` network
- Forwarded values are normalized to a bare IP before fingerprinting
- Invalid/opaque values such as `unknown` are rejected
- IPv4-mapped IPv6 is normalized back to IPv4 before family/network/block derivation

### 9. Credential/Network Telemetry Privacy

**Threat**: External validation telemetry leaks raw API credentials or raw source addresses.

**Mitigations**:
- HMAC-SHA256 fingerprinting occurs locally under a customer-held tenant salt
- Only the first 32 lowercase hexadecimal characters are emitted
- Exact address, network, and block values are fingerprinted separately
- Raw credentials and raw IP addresses are not written to the event output
- Static transport mapping is implemented; live baseline and external alert-quality results are not assumed by the local implementation

### 10. Tool Schema Drift

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
| Audit logger | Unavailable | Missing or incomplete evidence | Behavior is path/configuration dependent; a continued inspection must not be mistaken for a fail-closed, auditable production operation. Release gate remains open |
| Downstream MCP server | Crash | Connection error | Error propagates to caller |
| Rate limiter | Exhausted | Requests rejected | Operational endpoints exempt |
| Configuration | Missing API credentials | Auth bypass risk | Protected requests rejected; production config fails validation when no valid credential set is configured |

---

## Additional unresolved threats

- A client or local principal can bypass the gateway when it can connect to an unfenced downstream server, invoke another transport or modify host files directly. Legacy first-party mode and operator/daemon capabilities are outside the protected laboratory contract.
- Cooperative SQLite revocation and effect journaling do not supply distributed authorization freshness, cross-host exactly-once execution or recovery of arbitrary external side effects.
- A compromised operator, host root or Docker daemon can override process and mount restrictions; a hash chain alone does not provide tamper-proof off-host retention.
- Production TLS/authentication, trusted policy custody, DNS/redirect fencing, cancellation and unsolicited-message handling require end-to-end verification in the deployment topology.

## Scope Limitations

1. **Not a network firewall**: Egress policy returns decisions but does not intercept packets.
2. **Not an OS-level sandbox**: Process-event evaluation requires externally supplied events.
3. **Not a complete DLP solution**: PII detection is heuristic, not exhaustive.
4. **Detection is heuristic**: False positives and false negatives are possible.
5. **Enforcement is external**: The integrating runtime must honor returned decisions.
6. **Single-process trust**: The gateway trusts its own process memory and configuration.
7. **Trusted-edge dependency**: Correct forwarded-source attribution depends on operator-controlled infrastructure actually overwriting/sanitizing forwarded headers.
8. **Telemetry validation boundary**: Local event generation does not prove external ingestion correctness, live-baseline quality, or alert efficacy.

---

## Related Documents

- [`SECURITY.md`](SECURITY.md) — Security policy and vulnerability reporting
- [`SECURITY_AUDIT.md`](SECURITY_AUDIT.md) — Security review and validation notes
- [`README.md`](README.md) — Architecture, failure semantics, and operational guidance
