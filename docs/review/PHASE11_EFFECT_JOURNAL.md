> **Evidence reconciliation (2026-11-11; historical phase/snapshot):** Historical results below retain their original dates and denominators. Latest tested Phase 1–16 development SHA is `43a72c8984bf9a472b9055d4f9e84cc759f61718` ([CI](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42971171992): 1,211 passed, 6 skipped per Python version), **not** a merged or production-approved release. Offline research tests require no paid provider or provider-issued API keys; deployed HTTP authentication and unverified real credential revocation remain separate. See [operating restrictions](../../PRODUCTION.md) and [release evidence](../../docs/review/PHASE1_16_RELEASE_CANDIDATE_NO_GO_20261110.md).

# Phase 11 — Durable side-effect intent journal (pilot)

> **Integration-documentation review (2026-11-09):** A recorded intent, unknown outcome and confirmed effect are separate states. No exactly-once delivery, external rollback or crash-proof reconciliation is claimed. The development integration is [draft PR #167](https://github.com/poojakira/mcp-agent-security-gateway/pull/167), **not a production-approved release**.
## Security goal

Prevent accidental **automatic repeat dispatch** of explicitly selected
MCP write-style tool operations after a crash, cancellation, downstream
timeout or unknown response.

A trusted embedding application may opt in with `effect_journal` and
`effect_tools`. Selected `tools/call` requests must include a stable
operator-managed `params._gateway_operation_key` and an already trusted
authenticated principal. The gateway strips the operation-key field from
the downstream request, commits an `UNCERTAIN` intent to durable SQLite
**before** sending, and updates that intent to `COMPLETED` only after
the gateway has accepted a valid downstream success response.

Every repeated operation key is denied, **including** completed operations.
This avoids blindly replaying a write: it does NOT replay a previously
completed result, provide exactly-once execution, or support automatic retry.
A crash after reservation but before dispatch is an intentional conservative
false positive. An unknown/failed response remains uncertain indefinitely
until a trusted human/operator reconciles the real downstream side effect.

## Pilot boundaries

- SQLite WAL, synchronous FULL, unique composite operation scope, serialized
  transaction, no implicit runtime recreation of a missing store.
- A single selected effect request per message; batches with effects fail
  closed. Calls without an ID cannot execute a selected effect.
- All existing proxy authorization, policy, injection, response validation
  and revocation checks remain in place.
- The journal must be placed on a protected trusted filesystem and
  operator-provisioned ahead of time; no agent should have write access.
- The stable key is a caller-provided value with strict validation. The
  gateway does not authenticate its origin independently or provide
  distributed key custody.
- A test-only local SQLite snapshot cannot establish safe cross-host
  consensus, shared filesystem reliability, durability under complete disk
  loss, or secure reconciliation.
- **No rollback is promised:** an already-executed downstream effect is not
  undone by a rejected response.
- Future work: reconciliation workflow, true downstream idempotency support,
  crash/power-loss fault injection, host storage security, outage telemetry,
  concurrency stress and representative environment verification.

No paid services, production targets, customer information, or deployments.
This first pilot is only complete once CI passes on the exact source commit.


## Verified Phase 11 journal milestone

**Exact source commit:** `f262493112578addc0d7a6f244d8009ae744f59e`.
**CI evidence:** [run #42542628588](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42542628588), completed **successfully (3/3 jobs)**.

| Validation | Verified result |
|---|---|
| Python 3.10 full repository suite | 1,076 passed, 3 skipped; 83.07% coverage |
| Python 3.11 full repository suite | 1,076 passed, 3 skipped; 83.04% coverage |
| Python 3.12 full repository suite | 1,076 passed, 3 skipped; 83.04% coverage |
| Focused journal, concurrency, policy security regressions | 38 passed on each version |
| Ruff lint and formatter | Passed |
| Synthetic restart from UNCERTAIN reservation | Passed; repeat dispatch denied |
| Timeout and downstream error outcome handling | Passed; uncertain remains, no automatic retry |
| Concurrent second store instance duplicate reservation | Denied |
| Real crash/power-loss or production infrastructure fault injection | **Not tested** |
| Paid services / production deployment | None |

## Exit decision

**Phase 11 local side-effect intent journal: COMPLETE as a scoped prototype.**
**Phase 11 production recovery and exactly-once-effect safety: OPEN.**

The journal does not undo effects, provide a downstream transaction, or
guarantee exactly-once execution. A malicious or buggy client that changes
the operation key can still submit a new operation: stable keys need trusted
caller issuance. A database loss, corrupted or manipulated journal,
filesystem compromise, disabled journaling on an unconfigured tool, and
untrusted operation-key generation remain production hazards. The
`UNCERTAIN` state requires independent operator reconciliation before
any reconsideration of the real-world outcome.

The parent PRs remain drafts and are not merged by this pilot.
