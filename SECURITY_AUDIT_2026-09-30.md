# Security Audit — 2026-09-30

## Scope
Initial pre-remediation review of the current `main` branch.

## Runtime surface
Authenticated MCP inspection service, dashboard/realtime server, SIEM shipping, alerting, identity telemetry, Docker/Kubernetes deployment.

## Verified controls
- Protected inspection endpoints authenticate using configured API keys.
- Production rate limiting, circuit breaking, request limits, WAL/audit persistence, readiness, tracing, and metrics are implemented.
- Client-facing 500 responses are generic in the production server.
- Credential-looking values inspected in source are detection fixtures/canaries rather than confirmed live credentials.
- CI, Dependabot, security-hygiene workflow, and security documentation are present.

## Findings to remediate/verify
1. Review all outbound alert/SIEM destinations for HTTPS allowlisting, timeouts, and SSRF resistance.
2. Review dashboard/realtime endpoints for the same authentication boundary as production inspection endpoints.
3. Ensure shadow mode cannot be accidentally enabled in production without an explicit deployment setting.
4. Verify telemetry never persists raw API keys, authorization headers, source secrets, or request bodies.
5. Stress-test parser limits, slow-client handling, large JSON nesting, and connection exhaustion.
6. Verify critical alert delivery and health-gated rollback/blue-green deployment.

## Not applicable
Password reset and SQL tenant isolation unless an end-user account database is introduced.
