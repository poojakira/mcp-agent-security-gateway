# White-Box Application Security Assessment — 2026-10-05

This document records an owner-authorized application-security assessment of the MCP Agent Security Gateway.

## Method

The review combined:

- source inspection of the production HTTP and JSON-RPC boundaries;
- review of authorization, egress, rate-limit, audit, and telemetry code;
- review of the repository's current automated tests that exercise those boundaries;
- verification of documented limitations against the implementation.

No external production target, customer environment, or third-party system was scanned.

## Assessment matrix

| Area | Result | Notes |
|---|---|---|
| Authentication | PASS with deployment assumptions | Protected production inspection/metrics endpoints require configured credentials. |
| Authorization | PASS for supported enforcing paths | Default-deny server/capability policy is implemented; callers must use an enforcing integration path. |
| HTTP request smuggling / ambiguous framing | PASS for covered cases | Duplicate Content-Length and Transfer-Encoding are rejected; strict request target and header limits are tested. |
| JSON ambiguity | PASS for covered cases | Duplicate JSON keys and malformed JSON-RPC are rejected in the proxy path. |
| SSRF / egress | PASS for policy-controlled destinations | Private/loopback/link-local destinations are blocked unless allowlisted. |
| Request-size abuse | PASS for implemented limits | Request line, headers, and bodies are bounded. |
| Rate limiting | PARTIAL | Global in-process budget does not provide per-caller availability isolation. |
| Error disclosure | PASS for production HTTP boundary reviewed | Unexpected request failures return a generic internal error response. |
| Auditability | PASS for repository scope | WAL, hash-chained audit, ECS/SIEM evidence exist and are tested. |
| TLS | DEPLOYMENT CONTROL | TLS/mTLS is expected at ingress/service mesh, not terminated by the app. |
| Detector completeness | NOT CLAIMED | Heuristic content detectors can produce false positives/negatives. |

## Evidence

A dedicated, read-only **Focused AppSec Regression** run completed successfully on GitHub Actions:

- Workflow run: `37369244496`
- Tested PR head: `df28f426b95dddb60aac11b1e6c7bccd3aa4948e`
- Python: 3.12
- Result: **116 passed in 4.54s**
- Selected files:
  - `tests/test_http_framing.py`
  - `tests/test_protocol_hardening.py`
  - `tests/test_policy_enforcement.py`
  - `tests/test_production.py`

This focused count is separate from the repository-wide **723-test / 81.91% coverage** snapshot. It supports only the selected application-security regression boundary and is not a penetration-test coverage metric.

See `docs/APPSEC_CASE_STUDY.md` for the recruiter-facing case study and direct references to the relevant code/tests.

## Claim boundary

This review supports the statement **"performed a white-box application-security assessment of my own agent gateway and documented controls, evidence, and residual risks."**

It does **not** support the statements **"independent penetration tested," "production proven," "zero vulnerabilities,"** or **"prevents all prompt injection/SSRF/exfiltration attacks."**
