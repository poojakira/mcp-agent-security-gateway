# Phase 8 — Signed durable local authorization (multi-process pilot)

This is a **same-host multi-process prototype**, not a production distributed
permissions service. It extends the existing Phase 4 `ACLGuard(authority_check=...)`
and Phase 7 `OfflineJWKSVerifier(is_active=...)` operator interfaces without
changing their default behavior.

## Design

- One **operator-owned, access-restricted SQLite file** contains a canonical
  grants snapshot and revoked `(tenant, sid, jti)` triples.
- Every revision is authenticated with an HMAC-SHA256 using a trusted 256-bit
  minimum secret, held **outside the database**. Synthetic tests use a
  disposable test-only secret; real secrets must not be passed on CLI,
  logged, or committed.
- Read operations open SQLite read-only and always re-verify revision,
  snapshot structure and HMAC. They **never use a cached allow decision**.
- Writers perform `BEGIN IMMEDIATE` and compare a mandatory
  `expected_revision` before committing a single complete signed snapshot.
  Stale writes fail closed and cannot silently regrant a revoked resource.
- Each reader remembers the highest revision observed in memory, and can
  accept an **operator-trusted minimum_revision** after restart to reject
  previously signed stale states.
- A live gateway checks the store before forwarding protected tools and
  again before returning their results, using existing ACL guards.
- A local test uses two independent long-running Python processes with
  stale local permission caches, both observing one revocation.

## Threat boundaries and important limitations

- **Same trusted host only:** SQLite file locking is not a verified
  multi-host consensus protocol. Do not share this file over network
  filesystems or call it high availability.
- **No external authenticated event feed** or networked authority.
  Authenticity is from operator-only HMAC key custody and controlled
  SQLite filesystem access.
- **Rollback cannot be fully solved with an HMAC:** An older valid signed
  database restored after a restart will pass unless a trusted independent
  revision checkpoint is supplied. This pilot **explicitly tests and
  documents** that limitation.
- Revocation checks are immediate **on the next read after a committed
  transaction** on the same host; there is no guaranteed global latency SLA.
- Already-executed tool side effects cannot be rolled back.
- A stolen HMAC key, compromised host/database, or attacker able to replace
  both the database and its external revision anchor breaks this prototype.
- Running SQL operations and a callback synchronously under an ACL lock is
  not a production performance or availability design.
- The JWT session revocation callback is available but does not itself
  establish real OIDC client authentication.

## Phase gate

The **local multi-process durable prototype** may be accepted after
cross-version CI, actual subprocess tests, tamper/replay/rollback tests and
full gateway regression verification. **Production distributed
authorization remains OPEN** until a real authenticated, durable,
fault-tolerant authority, external rollback anchor, failover and restart
experiments are verified in an authorized environment.

No paid service, private runner, production deployments, real user data,
or external customer targets. All ancestor PRs must remain draft and
unmerged.
