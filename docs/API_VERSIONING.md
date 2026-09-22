# API Versioning

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

Production configuration requires a service key of at least 32 characters.
Protected requests send it in `X-API-Key`. Health and readiness remain
unauthenticated for orchestration probes. Metrics are protected because they
expose operational security telemetry.
