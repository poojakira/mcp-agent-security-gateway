# Security Review Case Study: Agent-to-Tool Execution Boundary

**System:** MCP Agent Security Gateway  
**Assessment type:** Authorized application-security review of a repository owned by the maintainer  
**Scope:** Routed MCP/JSON-RPC control-plane and policy-enforcement paths  
**Evidence boundary:** Repository source, committed tests, and GitHub Actions. This is not a third-party penetration test or a claim of production compromise resistance.

## Security question

An AI agent can turn model output into privileged actions. The review asks a narrower engineering question:

> What must be true before a routed agent tool call is allowed to reach a downstream tool, and how does the system behave when request framing, authorization, policy evaluation, or inspection fails?

## Trust boundary

```text
AI agent / MCP client
        |
        v
HTTP or stdio ingress
        |
        +--> strict framing / JSON-RPC validation
        +--> API-key authentication
        +--> capability + server authorization
        +--> prompt-injection / PII / exfiltration signals
        +--> process + egress policy, including anti-SSRF checks
        +--> rate limiting / circuit breaker
        +--> tamper-evident audit + telemetry
        |
        v
ALLOW --> downstream tool
BLOCK --> no downstream execution
```

Only traffic routed through the supported gateway path receives these controls.

## Threats reviewed

| Threat | Security decision | Evidence |
|---|---|---|
| Missing or invalid API credential | Reject protected inspection endpoints | Production-route authentication tests |
| Ambiguous HTTP framing | Reject duplicate Content-Length and Transfer-Encoding | `tests/test_http_framing.py` |
| Oversized headers / payloads | Bound request resources and reject oversized input | HTTP framing and protocol-hardening tests |
| Malformed / deeply nested JSON | Return bounded client error or fail closed; never treat malformed input as trusted | Protocol-hardening and production tests |
| Unauthorized MCP server/capability | Default deny | Policy-enforcement tests |
| SSRF / disallowed egress | Deny loopback or non-allowlisted destinations before forwarding | Policy-enforcement tests |
| Dangerous tool request | Deny wins over an otherwise allowed server | Policy-enforcement tests |
| Detector / circuit-breaker failure | Fail closed rather than forward | Production tests |
| Information leakage through processing errors | Return generic processing error at the HTTP boundary | Production server error handling |
| Auditability | Record request/audit metadata and emit security telemetry | WAL, audit, SIEM, and telemetry tests |

## Representative attack path

1. An agent produces a tool call containing a destination such as `http://127.0.0.1:8080/admin`.
2. The call is routed through the gateway.
3. The policy decision point evaluates the destination against the egress policy and anti-SSRF rules.
4. The decision is **deny**.
5. The enforcement path verifies that the downstream transport is **not called**.
6. The decision remains available to audit/telemetry paths for review.

The important property is not merely that a detector flags the request; the enforcement test asserts that a denied request never reaches the mocked downstream transport.

## Review methodology

The dedicated `Authorized AppSec Assessment` GitHub Actions workflow executes the existing security regression files that exercise:

- authentication failure paths;
- hostile and malformed HTTP framing;
- JSON-RPC size/depth/structure handling;
- fail-closed policy enforcement;
- SSRF/egress denial;
- rate limiting and circuit-breaker behavior;
- protected metrics/control-plane routes;
- generic error behavior and operational readiness.

This uses committed, reproducible tests rather than an unaudited manual claim.

## Findings and boundaries

The review demonstrates implemented controls for the tested repository paths. It does **not** establish:

- universal prompt-injection prevention;
- immunity to every parser/proxy discrepancy;
- production-scale availability or latency;
- effectiveness for traffic that bypasses the gateway;
- independent penetration-test certification;
- customer deployment or SOC adoption.

## Recruiter / hiring-manager takeaway

This project demonstrates an application-security workflow rather than only a security feature list:

**threat model -> trust boundary -> abuse case -> preventive control -> enforcement test -> telemetry/evidence -> documented residual risk.**

For current quantitative repository metrics, use [VERIFIED_METRICS.md](../VERIFIED_METRICS.md).
