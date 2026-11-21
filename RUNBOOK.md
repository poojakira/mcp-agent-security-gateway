# Operations runbook

## Choose the correct surface

| Surface | Entry point | Default address | Boundary |
|---|---|---|---|
| Local execution workbench | `python -m mcp_monitor.workbench` | `http://127.0.0.1:8761` | Real first-party fixture execution; one trusted local operator |
| Optional HTTP inspection service | `mcp-gateway` | `http://127.0.0.1:8080` | Authenticated inspection decisions; integrating caller must honor them |
| Legacy real-time dashboard | `python run_realtime.py` | Port 8000 | Visualization/control-plane development; not the workbench or execution proof |

No surface is approved for production merely because its code or deployment example exists. See [release gates](PRODUCTION.md). Do not route the local workbench through a public tunnel or reverse proxy.

## Local workbench startup and shutdown

Use [README setup](README.md#start-locally). Start `python -m mcp_monitor.workbench`; use `--port 8765` if 8761 is already owned by another process. Open the exact printed IPv4-loopback address. No API credential, database, migration or optional server extra is needed.

```sh
curl http://127.0.0.1:8761/health
```

Health reports software version, protocol subset and Git source/status when available. It is liveness/provenance metadata, not a readiness test for arbitrary external servers. An installed wheel correctly reports source `UNKNOWN`; do not substitute an enclosing repository's commit.

Stop with Ctrl+C. Normal execution stops the owned child and deletes its temporary directory before responding. Abrupt host termination may leave temporary files. Stop only the process you own; do not kill every Python process or delete another operator's workspace.

## Data lifecycle

Requests, responses and raw note content exist in browser/process memory and the per-run temporary directory. Every execution starts a new synthetic target. Reloading loses the in-browser comparison; there is no durable case store or backup operation. Explicit downloads remain wherever the operator saves them. Redacted exports remove raw request/response/note fields, but retain tool names, metadata, receipts and unkeyed audit entries. Filesystem deletion is not cryptographic erasure.

## Troubleshoot the actual result

| Observation | Meaning and recovery |
|---|---|
| Browser cannot connect | Check the owning terminal, chosen port and printed address. Do not widen the bind address. |
| HTTP 403 | Use the exact `127.0.0.1` origin and port. Proxying/alternate Host is intentionally refused. |
| HTTP 400/413/415 | Correct the bounded JSON payload/content type. The UI constructs the supported envelope. |
| HTTP 429 | The serial server's 30-request/minute budget is exhausted; wait for refill. |
| `NOT_INVOKED` | No operation was sent. Inspect parse/authorization/injection reasons before changing input or permissions. |
| `UNKNOWN / REQUIRES_RECONCILIATION` | A forwarded operation lacks sufficient confirmation. Do not infer success or automatically retry an external effect. |
| HTTP 500 | Engine failure; no successful outcome is established. Preserve non-secret source/configuration metadata and reproduce locally. |
| Editor or controls changed after a completed run | The previous report remains available and still describes its submitted request/hash. Execute again before treating the edited buffer as tested; edits alone do not invalidate completed evidence. |

A permission comparison starts another fresh disposable target. It is not rollback, idempotent replay or reconciliation of an external provider action. The repeat option deliberately demonstrates duplicate effects.

## Separate HTTP inspection service

The service's actual API/configuration reference is [API_VERSIONING.md](docs/API_VERSIONING.md#separate-http-inspection-service). It returns decisions; `GatewayClient` defaults to fail closed, but callers bypassing an enforcing integration are outside that boundary. Run `mcp-gateway --help` for the supported CLI. There is no `python -m mcp_monitor` application entry point, config-reload subcommand or password-reset flow.

Production-mode configuration validates credentials, approved server IDs, persistence paths and limits at startup. This is a configuration mode, not a release certification. Preserve API credentials/tenant salts in an operator-controlled secret store. Rotate at the relevant provider/deployment, recreate services when environment changes, and never put values in logs or source. Do not activate optional external telemetry during a local workbench evaluation.

[Compose](docker-compose.yml) and [Kubernetes examples](deploy/k8s/README.md) require operator-owned credentials, storage, image digests and deployment-specific review. File WAL/audit state is single-writer; do not increase replicas sharing those paths. The unauthenticated ELK lab is [a separate local experiment](detection_lab/README.md).

## Incident response and rollback

For a workbench failure, preserve the exact source commit, clean/dirty status, non-secret configuration, report outcome and reproducible synthetic input. Report privately using [SECURITY.md](SECURITY.md). Do not publish user inputs or credentials.

Stop the owned process, choose a previously reviewed commit in a separate checkout or worktree, install that version in a separate virtual environment and run its checks before using it. This avoids overwriting local modifications. No default-branch history rewrite is needed. It does not revoke credentials or undo external actions.

[INCIDENT_RUNBOOK.md](INCIDENT_RUNBOOK.md) provides an environment-specific response template. On-call staffing, response deadlines, recovery times and production backup/restore must be supplied and exercised by an operator; this repository establishes none of them.
