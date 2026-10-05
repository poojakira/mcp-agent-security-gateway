# Application Security Case Study: MCP Agent-to-Tool Boundary

**Assessment date:** 2026-10-05  
**System:** MCP Agent Security Gateway  
**Scope:** White-box review of the repository's production HTTP control plane, JSON-RPC inspection path, policy enforcement boundary, and security telemetry.  
**Authorization:** Owner-authorized assessment of this repository.  
**Claim boundary:** This is a source-assisted application-security assessment backed by repository tests. It is **not** an independent third-party penetration test and does not claim production deployment or universal attack prevention.

## Security question

An AI agent can turn model output into privileged actions. The security boundary is therefore not only the model response; it is the transition from an agent-generated request to a downstream tool that can read data, send messages, access a network, or execute an operation.

The review asks:

1. Can malformed or ambiguous requests reach the decision layer?
2. Can callers bypass authentication or authorization?
3. Can tool arguments pivot into disallowed network destinations?
4. Can abusive traffic exhaust or destabilize the gateway?
5. Are blocked/failed decisions reviewable after the fact?

## Reviewed attack surface

- Production HTTP endpoints: `/v1/inspect_call`, `/v1/inspect_output`, `/v1/metrics`, `/v1/health`, `/v1/ready`
- JSON-RPC parsing and duplicate-key handling
- API-key authentication and configured multi-key support
- Server/capability authorization and policy-as-code enforcement
- Anti-SSRF egress decisions
- Payload/header/request framing limits
- Rate limiting and circuit breaking
- Audit/WAL, ECS telemetry, Elastic detection rules, and SIEM tests
- Stdio proxy enforcement path

## Threat-to-control review

| Threat | Implemented control | Repository evidence |
|---|---|---|
| Missing or invalid service credential | Protected production inspection/metrics endpoints require a configured API key and compare credentials without plain equality | `src/mcp_monitor/production/server.py`, `tests/test_production.py` |
| Malformed / ambiguous HTTP framing | Strict origin-form request parsing, duplicate Content-Length rejection, Transfer-Encoding rejection, request/header size caps, method/version checks | `src/mcp_monitor/production/server.py`, `tests/test_http_framing.py` |
| JSON ambiguity | JSON-RPC parsing rejects malformed input and duplicate object keys | `src/mcp_monitor/proxy/stdio_proxy.py`, `tests/test_stdio_proxy.py` |
| Unauthorized tool/server use | Default-deny policy and explicit server/capability checks before downstream execution | `src/mcp_monitor/policy/policy_engine.py`, `tests/test_policy_enforcement.py` |
| SSRF / egress pivot | Private, loopback, and link-local destinations are denied unless explicitly allowlisted | `src/mcp_monitor/policy/policy_engine.py`, policy tests |
| Oversized request / resource abuse | Request-body and header limits, rate limiting, circuit breaker, fail-closed production configuration | production server/config tests |
| Sensitive or suspicious agent arguments | Normalization, prompt-injection patterns, PII/exfiltration signals, process/egress policy checks | detector and regression suites |
| Loss of forensic evidence | WAL + hash-chained audit path, ECS-formatted telemetry, Elastic rules and SIEM tests | audit/WAL tests and SIEM test suites |

## Verified behavior

The current repository evidence records **723 passing tests at 81.91% statement coverage**, with the same suite green across Python 3.10-3.12. The repository also records **9 Elastic Security rules** and **21 core SIEM tests**. Those values are repository verification evidence, not claims of customer deployment or universal detector efficacy.

Focused tests relevant to this review include:

- `tests/test_http_framing.py`: rejects duplicate Content-Length, Transfer-Encoding, absolute-form request targets, oversized header lines, and unsupported methods.
- `tests/test_production.py`: exercises authentication, API endpoints, rate limiting, circuit breaking, logging, metrics, tracing, and production configuration.
- `tests/test_policy_enforcement.py`: verifies denied tool calls do not reach downstream transport while allowed calls can.
- `tests/test_stdio_proxy.py`: verifies malformed JSON / duplicate-key handling and proxy enforcement.
- `tests/test_client.py`: verifies client-side API-key propagation and blocking semantics.

## Findings and architectural limitations

### APPSEC-MCP-01 — Shared process-wide rate-limit budget
**Severity:** Low / availability design limitation

The production HTTP server uses one in-process token bucket for non-operational endpoints. A noisy authenticated caller can therefore consume capacity that affects other callers in the same process.

**Impact:** Availability isolation between callers is weaker than a per-identity or distributed limiter.

**Recommended production treatment:** move enforcement to a per-identity/shared backend or an upstream distributed control when multi-client isolation is required.

### APPSEC-MCP-02 — TLS is a deployment responsibility
**Severity:** Informational

The application service itself does not terminate production TLS. Kubernetes documentation expects TLS/mTLS termination at ingress or service mesh.

**Impact:** A deployment that exposes the plaintext service directly would weaken transport confidentiality/integrity.

**Recommended production treatment:** require TLS at ingress and mTLS/service identity where the environment needs zero-trust east-west transport.

### APPSEC-MCP-03 — Enforcement depends on the selected integration path
**Severity:** Informational

The gateway can enforce before downstream execution on supported proxy/policy paths, but a caller that only consumes an inspection result must honor the returned decision.

**Impact:** Security guarantees depend on routing privileged tool execution through an enforcing path.

**Recommended production treatment:** prefer integrations where a denied call cannot invoke downstream transport.

### APPSEC-MCP-04 — Trusted-edge dependency for source attribution
**Severity:** Informational

Forwarded-source identity is only trustworthy when operator-controlled infrastructure overwrites or sanitizes forwarding headers.

**Recommended production treatment:** document trusted proxy boundaries and reject externally supplied forwarding headers at the edge.

### APPSEC-MCP-05 — Heuristic content detection is not a proof of absence
**Severity:** Informational

Prompt-injection, PII, and exfiltration signals are heuristic and can have false positives and false negatives.

**Recommended production treatment:** keep authorization and deterministic policy controls separate from heuristic detection, and treat detectors as signals rather than universal prevention.

## Result

The reviewed implementation shows a defensible application-security boundary for an agent-to-tool gateway: strict protocol parsing, authenticated control-plane access, default-deny authorization, egress restrictions, abuse controls, and reviewable telemetry. The main remaining risks are architectural/deployment boundaries rather than undocumented claims of perfect detection.

For recruiters and hiring teams, the useful evidence is the review method itself: **threat model → attack surface → control → verification → limitation**, not only the raw test count.
