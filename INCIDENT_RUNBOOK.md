# Incident-response template

This is an operator-adaptable template, not a record of an operated service. The project provides no on-call rotation, SLA, recovery-time guarantee or live deployment. Populate contacts and deadlines in your own private operational system before relying on them. The [runbook](RUNBOOK.md) distinguishes the local workbench, HTTP inspection service and legacy dashboards.

## Triage and preserve

1. Identify the exact surface, source commit/image digest, configuration and affected operations. A policy decision, child invocation and confirmed external effect are different observations.
2. Preserve non-secret reports and, for the optional HTTP service, its configured WAL/audit files. Record UTC times, request/trace IDs, symptoms, actual errors and evidence custody. Do not copy credentials, private input or authorization headers into incident tickets.
3. Determine severity from actual impact. A confirmed enforcement bypass or unintended privileged effect is urgent; a rendering issue may have lower impact. Use operator-defined response targets rather than invented repository SLAs.
4. Contain the affected integration through controls you own. Keep fail-closed behavior and current evidence; do not disable authentication, limits or readiness merely to restore apparent availability.
5. Notify the operator's designated responder and report a repository vulnerability privately using [SECURITY.md](SECURITY.md).

## Useful observations

For the local workbench, use `GET /health`, the browser's source/status/outcome, actual response and receipt/state. `UNKNOWN / REQUIRES_RECONCILIATION` does not authorize an automatic retry. Normal execution deletes its child/workspace; abrupt shutdown can leave temporary data.

For an explicitly configured HTTP inspection service:

```sh
curl http://127.0.0.1:8080/v1/health
curl http://127.0.0.1:8080/v1/ready
curl -H "X-API-Key: $MCP_API_KEY" http://127.0.0.1:8080/v1/metrics
```

Use only a credential already configured for the authorized local service. Readiness checks writable persistence directories; it does not certify external delivery or safety. Source events, SIEM output and identity telemetry can be useful context, but their availability depends on configuration and successful delivery.

## Failure responses

| Failure | Safe response |
|---|---|
| Owned process crash/OOM | Preserve logs and input-size/configuration metadata; stop/restart only the owned process after investigation. Confirm health and a bounded synthetic workflow. |
| Policy/detector error | Retain the denying/unknown result; reproduce with synthetic data before changing rules. Do not make errors allow traffic. |
| False-positive surge | Record matched rules and legitimate cases, add representative regression evidence, then review the scoped fix. No unreviewed broad bypass. |
| Suspected bypass | Isolate the affected integration, preserve source/configuration and actual effect evidence, revoke compromised credentials separately, and privately disclose reproducible findings. |
| Configuration or identity drift | Compare deployed values/hashes against operator-controlled known-good configuration. Recreate the service to apply changed environment variables; restart alone may not apply them. |
| WAL/audit storage failure | Preserve existing data and repair ownership/capacity. Do not bypass readiness or delete forensic state to make probes pass. |
| Ambiguous external effect | Reconcile with the authoritative provider/receipt before retrying. The workbench has no durable provider journal or exactly-once contract. |

## Recovery and rollback

Use a separate reviewed checkout and virtual environment, or an immutable previously validated image. Restore explicit compatible configuration and operator-managed state. Verify authentication/denial, writable persistence, actual synthetic task and source identity before restoring traffic. Do not rewrite Git history or overwrite another operator's uncommitted work. Code rollback does not rotate credentials, undo a sent message or reverse other provider actions. Production backup/restore and recovery times require an environment-specific exercised plan.

## Record and review

Capture summary, actual impact, UTC timeline, root cause, detection method, evidence IDs, containment/recovery actions, residual risk and follow-up owner/due date. Distinguish observed facts from hypotheses and synthetic reproductions from actual incidents. Review which acceptance tests would prevent recurrence; no fixed response or postmortem deadline is asserted by this repository.
