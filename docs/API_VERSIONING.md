> **Evidence reconciliation (2026-11-11; living reference):** Historical results below retain their original dates and denominators. Latest tested Phase 1–16 development SHA is `43a72c8984bf9a472b9055d4f9e84cc759f61718` ([CI](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42971171992): 1,211 passed, 6 skipped per Python version), **not** a merged or production-approved release. Offline research tests require no paid provider or provider-issued API keys; deployed HTTP authentication and unverified real credential revocation remain separate. See [operating restrictions](../PRODUCTION.md) and [release evidence](../docs/review/PHASE1_16_RELEASE_CANDIDATE_NO_GO_20261110.md).

# API Versioning

> **Evidence and release status (2026-11-09):** The API-versioning policy describes intended compatibility; only the explicitly implemented endpoints/transports and tested integration matrix can be treated as supported. The [release review](../docs/review/PHASE13_RELEASE_READINESS.md) remains **NO-GO**, and [PR #167](https://github.com/poojakira/mcp-agent-security-gateway/pull/167) is a draft integration candidate.
This document describes the versioning approach for the
`mcp-agent-security-gateway` HTTP inspection service
(`src/mcp_monitor/production/server.py`).

## Strategy

The service uses URL path versioning (`/v1/...`). This keeps the version
explicit in every request and makes routing and caching straightforward.

## Current endpoints (v1)

These are the endpoints actually implemented today. Verify against
`src/mcp_monitor/production/server.py`.

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| `POST` | `/v1/inspect_call` | X-API-Key | Inspect an inbound MCP tool call |
| `POST` | `/v1/inspect_output` | X-API-Key | Inspect a tool output/result |
| `GET`  | `/v1/health` | none | Liveness check |
| `GET`  | `/v1/ready` | none | Readiness check |
| `GET`  | `/v1/metrics` | X-API-Key | Service metrics |

There is no `v2` API. When one is introduced, it will be added to this table
with its release date, and this document will be updated in the same change.

## Compatibility policy

- Additive changes (new optional fields, new endpoints) are non-breaking and
  may ship within `v1`.
- Breaking changes (removing/renaming a field, changing status-code semantics)
  require a new version prefix (`/v2/`).
- When a new major version ships, the previous version enters a deprecation
  period before removal. The specific window will be documented here at that
  time rather than pre-committed now.

## Internal Python API

`MCPSecurityMonitor`, `AuditLog`, and `WriteAheadLog` are the exported public
Python API (`mcp_monitor.__all__`). Signature changes to these follow the same
additive-vs-breaking rule above.

## Authentication boundary

Production configuration requires at least one API credential of 32 or more characters. The legacy single-key variable `MCP_API_KEY` remains supported; `MCP_API_KEYS` adds a comma-separated set of stable credentials for per-credential attribution. Protected requests send the selected credential in `X-API-Key`. Health and readiness remain unauthenticated for orchestration probes. Metrics are protected because they expose operational security telemetry.

Credential/network telemetry is not a new HTTP API version. It is generated locally from the authenticated request path. The socket peer is authoritative unless the peer belongs to an explicitly configured trusted-proxy CIDR, in which case a normalized forwarded source may be used. Raw credentials and raw source addresses remain local to the gateway.
