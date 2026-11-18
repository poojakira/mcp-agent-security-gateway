# Documentation reconciliation — unreleased

- Consolidate current local workflow, API, security, operations, release and developer guidance around actual fixture execution.
- Distinguish the prior 829-test implementation-source proof from pending later-head results; publish immutable evidence without an evidence branch.
- Date historical/poster/native/lab assertions, remove unsupported effectiveness/certification/SLA claims, and record every tracked document's disposition.
- Correct API/module, dependency, rule-count, build-probe and deployment-scope drift; preserve legal and raw historical records.
- Record completed safe branch cleanup while retaining active/unique work. Update only a documentation-renderer heading and build-comment label outside prose; no runtime, security-gate, software release or deployment change.

# Local workbench candidate — unreleased

- Add a loopback browser request editor connected to the existing MCP proxy and policy engine.
- Add constrained first-party stdio tool execution, independent state observations, redacted exports and actual crash/repeat checks.
- Fix independently reproduced Python 3.10 timeout handling, unrelated-repository source attribution, and omitted repeat-count evidence.
- Fix the browser CI workflow's unavailable job-level context, validate expressions with pinned actionlint, and check out the exact candidate head for generated evidence.
- Install Git in the Docker builder for actual provenance regression fixtures; retain all regression assertions.
- Move current screenshots to generated source-scoped evidence; do not publish a dirty implementation preview as candidate evidence.
- Preserve advanced security branches; no production release or current legacy metrics claimed.
- Normalize five pre-existing documentation trailing line endings under the existing Git attributes.

# Historical changelog

Entries below are preserved project history. Their test counts, coverage and verification language describe earlier snapshots and do not attest to the local workbench candidate. Where an accessible run cannot be recovered, those historical verification claims remain NOT VERIFIED.

## Unreleased

- added direct smoke CLI tests for runtime configuration, successful redacted responses, and exception redaction
- added a vendor-neutral three-credential live smoke sender that selects one queued event per distinct credential fingerprint, sends a single HTTPS Bearer-authenticated batch, and redacts runtime secrets from status output
- completed the vendor-neutral live transport envelope: integer schema version `1`, client `mcp-gateway/1.0.0`, `backfill=false`, positional `event_fps`, and stable retry fingerprints derived from `"evt:" + event_id`
- renamed external-validation telemetry code, configuration, tests, and documentation to vendor-neutral identity telemetry naming
- refreshed authoritative verification to **707 passing tests** and **82.85% statement coverage** (5,342 statements, 916 missed) on the verified code snapshot `e249bde03affc6dcece172f991269cfe1c26417a`; full CI and Production Gate are green
- added stable multi-credential authentication through `MCP_API_KEYS` while retaining legacy `MCP_API_KEY`
- added trusted source-address capture: socket peer by default, with `X-Forwarded-For` accepted only from explicitly configured trusted proxy CIDRs
- added IPv4/IPv6 canonicalization, including IPv4-mapped IPv6 normalization
- added privacy-preserving credential/network telemetry helpers using locally computed HMAC-SHA256 fingerprints for credential, exact address, network, and block values
- added optional local external-validation transport output with zero token counts where MCP-layer token accounting is unavailable; static contract mapping is complete, while live baseline results are not claimed
- updated README, runbooks, deployment docs, threat model, evidence files, and poster Markdown companions to distinguish current verified evidence from historical snapshots

- added detection engineering lab (`src/mcp_monitor/siem/`): ECS (Elastic Common Schema) formatter, in-memory correlation engine with 6 multi-event attack rules, and log shippers (Elasticsearch bulk API, NDJSON file, stdout)
- added 6 Atomic Red Team style attack simulation scenarios (`mcp_monitor.siem.attack_simulations`)
- added 9 Elastic Security detection rules mapped to MITRE ATT&CK (`detection_rules/elastic_rules.toml`)
- added docker-compose ELK stack and Filebeat config for local detection practice (`docker-compose.detection-lab.yml`, `detection_lab/`); verified end-to-end on Docker Desktop (events ship to Elasticsearch with 0 errors)
- added 21 tests for the SIEM module (`tests/test_siem.py`)
- added failure semantics table, Known Limitations, and Verification sections to README; added THREAT_MODEL.md
- added RUNBOOK section 13 documenting the detection lab with verified commands

## 0.1.0 - 2026-07-10

- added prompt injection detection with 10 regex patterns
- added PII and secret detection with redaction support
- added shadow MCP server detection and trust scoring
- added exfiltration detection for BCC abuse, payload anomalies, and suspicious URLs
- added SHA-256 hash-chained audit log and WAL persistence
- added monitor orchestration, docs, CI, and 105 tests

