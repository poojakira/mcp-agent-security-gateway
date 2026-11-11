> **Evidence reconciliation (2026-11-11; living reference):** Historical results below retain their original dates and denominators. Latest tested Phase 1–16 development SHA is `43a72c8984bf9a472b9055d4f9e84cc759f61718` ([CI](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42971171992): 1,211 passed, 6 skipped per Python version), **not** a merged or production-approved release. Offline research tests require no paid provider or provider-issued API keys; deployed HTTP authentication and unverified real credential revocation remain separate. See [operating restrictions](../PRODUCTION.md) and [release evidence](../docs/review/PHASE1_16_RELEASE_CANDIDATE_NO_GO_20261110.md).

# Operational incident response measurement

> **Evidence and release status (2026-11-09):** This is a measurement design and scoped development exercise. Gateway decision latency and simulated blocking are not human incident response time or production MTTR. The [release review](../docs/review/PHASE13_RELEASE_READINESS.md) remains **NO-GO**, and [PR #167](https://github.com/poojakira/mcp-agent-security-gateway/pull/167) is a draft integration candidate.
Run `python scripts/measure_incident_response.py evidence/incident_timestamps.csv` with an **actual** exported, non-secret CSV file. Required columns:
`incident_id,cohort,scenario_id,occurred_at,acknowledged_at,contained_at,source,synthetic`.

- Timestamp values must include a UTC offset. `cohort` is `before` or `after`; `scenario_id` matches comparable scenarios across cohorts. A source is an auditable incident ticket or timestamped incident log reference; `synthetic` is `false` for actual data.
- Result contains median minutes from incident occurrence to acknowledgment and containment, and percentage change: `(baseline - after) / baseline * 100`.
- CSV is rejected for duplicates, missing scenarios, impossible timestamp sequences, missing source references, and synthetic cases. Only use `--allow-synthetic` for local demos, which are labeled synthetic.
- Comparing matched scenarios does not control for severity, staffing, attack complexity or response workflow. Record those dimensions in the incident source; report observational comparison, **not causal improvement**, without a valid study design.
- `occurred_at` is not necessarily detection time. If incident occurrence cannot be determined from telemetry, do not guess or use an alert timestamp as the true occurrence time.
- Gateways do not measure MTTR by timing `inspect_call`; actual resolution/containment requires a responder's documented actions. The gateway may block before a human incident exists. Do not imply every blocked call was a resolved incident.
- This workflow does not access your persistent pilot, change tokens, or make outside requests.
