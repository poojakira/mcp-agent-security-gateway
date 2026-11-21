# API and versioning reference

## Local workbench API

Source: `src/mcp_monitor/workbench/__main__.py` and `runtime.py`. This loopback-only HTTP adapter is not the separately authenticated `/v1` inspection service. Its software version is 0.1.0; tested MCP stdio subset is 2025-03-26. Those version strings do not establish latest-protocol conformance.

| Method | Path | Purpose |
|---|---|---|
| GET | `/` | Browser interface |
| GET | `/app.js`, `/style.css` | Static application assets |
| GET | `/health` | Liveness plus source/status/software/protocol metadata |
| POST | `/api/execute` | Run the supported request through actual policy/proxy/fixture |

Every request requires the exact IPv4-loopback Host; an Origin header, when supplied, must match. POST requires `Content-Type: application/json`, declared length 1–16384 bytes and no Transfer-Encoding. The JSON envelope accepts only `request`, `preset`, `guarded`, `repeats`; the request string is at most 8192 UTF-8 bytes. Presets are `read-only`/`read-write`, guarded is a boolean and repeats is 1 or 2. Omitted optional values select `read-only` / `true` / `1`.

Example envelope for an authorized local evaluation:

```json
{"request":"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"read_note\",\"arguments\":{}}}","preset":"read-only","guarded":true,"repeats":1}
```

A report contains `app_version`, `source_commit `, `source_status`, `protocol_version`, `trace_id`, UTC timestamp, input/configuration hashes, authorization, handshake, responses, outcome, error, actual tool state and ephemeral audit evidence. A successful HTTP 200 can contain a denied, failed or UNKNOWN operation. Interpret [outcomes](WORKBENCH.md#outcome-interpretation), not HTTP status alone. The browser's downloaded report redacts raw request/response/note content; direct API responses contain that data.

| HTTP status | Meaning |
|---|---|
| 400 | Invalid envelope/value/type or parsing error |
| 403 | Peer/Host/Origin boundary refused |
| 404 | Unsupported route |
| 413 | Declared body outside allowed bytes |
| 415 | Unsupported content type/framing |
| 429 | Local request budget exhausted |
| 500 | Engine failure; no success established |

`guarded=false` substitutes the read/write tool allowlist only. It does not disable injection, protocol or egress checks. User input cannot choose an executable, arbitrary host path or network target implementation. Installed wheels outside the tracked source root report source UNKNOWN. See [operations](../RUNBOOK.md) for lifecycle and privacy.

## Separate HTTP inspection service

Source: `src/mcp_monitor/production/server.py` and `config.py`. Launch with the installed `mcp-gateway` console entry point; the default address is 127.0.0.1:8080. It inspects supplied tool calls/outputs and returns decisions. It does not itself execute an arbitrary downstream MCP tool.

| Method | Path | Authentication | Purpose |
|---|---|---|---|
| POST | `/v1/inspect_call` | `X-API-Key` | Inspect inbound tool-call fields |
| POST | `/v1/inspect_output` | `X-API-Key` | Inspect supplied output/result |
| GET | `/v1/health` | None | Liveness |
| GET | `/v1/ready` | None | Check configured WAL/audit directories are writable |
| GET | `/v1/metrics` | `X-API-Key` | Operational counters |

Production-mode validation requires nonempty approved servers, valid limits, WAL/audit paths, no anonymous/shadow mode and at least one configured credential with all credentials at least 32 characters. `MCP_API_KEY` supplies a legacy single credential; `MCP_API_KEYS` supplies comma-separated stable credentials. The retired publicly exposed demonstration credential is rejected. Development defaults are not production approval. `/v1/ready` does not establish external delivery or durable provider effects.

For an already configured authorized local service:

```sh
curl -X POST http://127.0.0.1:8080/v1/inspect_call \
  -H "X-API-Key: $MCP_API_KEY" -H 'Content-Type: application/json' \
  -d '{"name":"read_file","server_id":"github","arguments":{"path":"README.md"}}'
```

The socket peer is authoritative unless it belongs to explicitly configured `MCP_TRUSTED_PROXY_CIDRS`; only then may a normalized forwarded value be used. The operator must ensure the trusted edge sanitizes forwarding headers. TLS termination and identity lifecycle remain deployment/integration responsibilities.

## Optional identity telemetry

Telemetry is separate from the local workbench. It is disabled unless `MCP_IDENTITY_TELEMETRY_ENABLED` is set. Production validation additionally requires `MCP_IDENTITY_TELEMETRY_TENANT_SALT` and `MCP_IDENTITY_TELEMETRY_OUTPUT`. Preserve salt/credential identities across an intended baseline; do not transmit real data during synthetic evaluation.

The queue stores `schema_version: 1` envelopes with client `mcp-gateway/1.0.0`, `backfill: false`, events and positional event_fps arrays. Event fingerprints are locally derived HMAC-SHA256 values truncated to 32 hex characters; raw credentials/source addresses/internal event IDs are not transport fields. Fingerprints are linkable metadata, not proof of anonymization. `mcp-identity-shipper` uses an HTTPS endpoint, runtime bearer token and durable byte-offset cursor; retry sends the stored envelope rather than inventing another identity. Its source modules and tests describe that integration. External ingestion, alert quality, privacy approval and production delivery are NOT VERIFIED by the browser workflow. Do not activate `identity_smoke` merely to reproduce offline workbench evidence.

## Other checked-in controls and boundaries

| Control | Source / test | What it establishes and what remains external |
|---|---|---|
| HTTP framing/input limits | `production/server.py`, `tests/test_http_framing.py` | Strict origin-form target, bounded request/header/body, duplicate Content-Length and Transfer-Encoding rejection on that service; not a generic reverse-proxy security assessment |
| Production credential/configuration checks | `production/config.py`, `tests/test_production.py` | Explicit anonymous opt-in exists for development; production validation rejects anonymous/shadow mode, absent/short credentials and missing required state/configuration |
| Trusted source attribution | `production/identity_telemetry.py`, telemetry/production tests | Normalize source context before fingerprinting; correct attribution still requires an operator-controlled trusted edge |
| Manifest integrity | `advanced/manifest.py`, `tests/test_advanced_manifest.py` | Operator-keyed HMAC comparison against an approved baseline; does not establish a publisher's initial trustworthiness or key custody |
| Behavioral drift/canary checks | `advanced/drift.py`, `advanced/canary.py` and corresponding tests | Compare supplied baseline/live data or configured probes; no autonomous proof of hidden external effects |
| Audit/WAL | `audit/log.py`, `audit/wal.py` and their tests | Local chain/persistence behavior; unkeyed workbench chains have no external anchor and a compromised host can rewrite state |
| Heuristic output/PII signals | `detectors/pii_detector.py`, `/v1/inspect_output` tests | Supplied-data heuristics on the separate inspection path; no complete DLP or local-workbench output filtering claim |

These source/test relationships describe checked-in semantics. They do not relabel prior tests as current-head runs or imply all optional controls are enabled in the browser.

## Compatibility

The inspection service has `/v1`, with no `/v2` implementation. Additive optional fields/endpoints may remain in that version; breaking changes require an explicit version/deprecation plan. The local adapter's unprefixed endpoints are scoped to its pre-1.0 local workflow. Do not infer identical endpoints, authentication or guarantees across surfaces. Exported Python names are `MCPSecurityMonitor`, `AuditLog` and `WriteAheadLog`; their existence is not a stable cross-version semantic guarantee.
