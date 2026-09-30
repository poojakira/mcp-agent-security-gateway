# Changelog

## Unreleased

- renamed external-validation telemetry code, configuration, tests, and documentation to vendor-neutral identity telemetry naming
- refreshed authoritative verification to **702 passing tests** and **82.76% statement coverage** (5,324 statements, 918 missed) on the verified code snapshot `59eeac5221ab4eff3d5c5e421ccb46407de08037`; full CI and Production Gate are green
- added stable multi-credential authentication through `MCP_API_KEYS` while retaining legacy `MCP_API_KEY`
- added trusted source-address capture: socket peer by default, with `X-Forwarded-For` accepted only from explicitly configured trusted proxy CIDRs
- added IPv4/IPv6 canonicalization, including IPv4-mapped IPv6 normalization
- added privacy-preserving credential/network telemetry helpers using locally computed HMAC-SHA256 fingerprints for credential, exact address, network, and block values
- added optional local external-validation event output with zero token counts where MCP-layer token accounting is unavailable; external pilot/ingestion approval is not claimed
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

