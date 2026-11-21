# Release and deployment governance

**Decision: PARTIAL. No production deployment is approved.** A configuration named `production`, a green workflow named Production Gate, or checked-in deployment manifests is not operational approval.

## Promotion requirements

A release requires a frozen candidate and fresh evidence identifying its exact commit, clean state, commands, environment, pass/fail/skip counts, coverage settings and artifact hashes. Required checks cover regression/integration, browser behavior, lint/type checks, security/dependency analysis, package/container build and runtime, documentation drift and release provenance. Preserve blocking thresholds and record failures or skips explicitly. [docs/EVIDENCE.md](docs/EVIDENCE.md) separates prior-source evidence from pending new-head results.

The local workbench still lacks credential expiry/revocation, arbitrary-server containment, output PII filtering, durable external-action reconciliation and complete current MCP conformance/cancellation/concurrency validation. Environment-specific security/privacy review, SLO/load evidence, immutable deployment images, trusted ingress/TLS, backup/restore and exercised rollback remain unverified. Do not expose the workbench to shared/public networks.

## Optional inspection-service controls

The separate HTTP service validates production-mode configuration, authenticates protected inspection/metrics routes, evaluates policy and records local audit/WAL evidence. It is not a general tool executor. Operators must route privileged actions through an enforcing integration and own credentials, storage, network controls and recovery. Read [API/configuration](docs/API_VERSIONING.md) and [operations](RUNBOOK.md) before considering any deployment.

Single-writer file-backed WAL/audit state does not support shared-file horizontal scaling. Readiness checks writable persistence directories, not external-effect durability or security efficacy. Optional identity telemetry adds external data delivery only when explicitly configured; its local fingerprint generation does not prove ingestion quality or lawful/appropriate use.

## Branch and change policy

The owner-selected remote branch set is `main` and `codex/local-workbench-20261116`. Additional dependency and unique-work branches were retired only after exact-tip annotated recovery tags and verified private backups; unreviewed changes were not merged. See [selected branches and recovery](docs/BRANCHES.md). Earlier branch counts/dispositions remain historical. Security automation and protected-main checks remain enabled.

A later change, including documentation, needs commit-scoped checks before its results are called current. Evidence-only archive tags are not releases. Review and merge decisions remain separate from package/container publication or deployment.
