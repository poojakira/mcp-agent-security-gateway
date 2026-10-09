# Operational incident response measurement

Run `python scripts/measure_incident_response.py evidence/incident_timestamps.csv` with an **actual** exported, non-secret CSV file. Required columns:
`incident_id,cohort,scenario_id,occurred_at,acknowledged_at,contained_at,source,synthetic`.

- Timestamp values must include a UTC offset. `cohort` is `before` or `after`; `scenario_id` matches comparable scenarios across cohorts. A source is an auditable incident ticket or timestamped incident log reference; `synthetic` is `false` for actual data.
- Result contains median minutes from incident occurrence to acknowledgment and containment, and percentage change: `(baseline - after) / baseline * 100`.
- CSV is rejected for duplicates, missing scenarios, impossible timestamp sequences, missing source references, and synthetic cases. Only use `--allow-synthetic` for local demos, which are labeled synthetic.
- Comparing matched scenarios does not control for severity, staffing, attack complexity or response workflow. Record those dimensions in the incident source; report observational comparison, **not causal improvement**, without a valid study design.
- `occurred_at` is not necessarily detection time. If incident occurrence cannot be determined from telemetry, do not guess or use an alert timestamp as the true occurrence time.
- Gateways do not measure MTTR by timing `inspect_call`; actual resolution/containment requires a responder's documented actions. The gateway may block before a human incident exists. Do not imply every blocked call was a resolved incident.
- This workflow does not access your persistent pilot, change tokens, or make outside requests.
