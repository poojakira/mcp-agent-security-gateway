# Phase 11 — Durable side-effect intent journal (pilot)

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
