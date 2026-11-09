# Phase 16 — Cooperative revocation-safe MCP commit fence

**Status: candidate only, production NO-GO.** This phase uses a free, local SQLite authority file and a first-party protected manifest MCP adapter. It does not need API keys, a provider account, or paid services.

## Trust boundary

A trusted operator provisions a local principal with `RevocationFence.bootstrap` in a private, non-symlink local authority database. The MCP client cannot choose the authority file or principal through `tools/call` arguments. Configure the protected MCP server using the following operator-controlled settings:

- `MCP_PROTECTED_REPO_ROOT`: operator-authorized absolute workspace.
- `MCP_APPROVED_DEPENDENCY_UPDATES`: exact operator-approved package/version mapping.
- `MCP_REVOCATION_AUTHORITY_DB`: existing private, single-link SQLite authority file.
- `MCP_TRUSTED_OPERATOR_PRINCIPAL`: provisioned operator identity.
- `MCP_REQUIRE_REVOCATION_FENCE=1`: reject startup when revocation authority or principal is missing.

**Important:** In the Phase 1–16 integration candidate, `MCP_ENV=production` requires the revocation fence and rejects `MCP_REQUIRE_REVOCATION_FENCE=0`. Outside production, the variable defaults to `0` for legacy laboratory compatibility. A lab launch without enforced mode is **not revocation-safe**. The current adapter cannot authenticate an arbitrary external client's principal; it relies on operator-controlled process configuration.

During `update_dependency`, the cooperating adapter holds `BEGIN IMMEDIATE` in the same SQLite authority until `os.replace` and its directory synchronization attempt finish. A revocation that commits before the writer acquires the lock denies the operation. A revocation that starts while the effect owns the lock cannot commit until the protected operation releases it. A subsequent protected operation after revocation fails closed. The current authorization revision cannot reverse an already executed effect.

## Evidence and adversarial tests

- Denial after revocation and across restart.
- Denial for unprovisioned identity and unavailable authority.
- Concurrency: revocation cannot durably complete midway through an already-authorized protected update.
- Rejection of partial enforced-mode startup configuration.
- Phase 15 consequence observer and Phase 11 effect journal regressions.

Run locally with free development dependencies using the Phase 16 workflow's test commands. The workflow checks Python 3.10/3.11/3.12; **CI green on the exact head is required** before declaring scoped laboratory completion.

## Release blockers

1. The legacy unfenced mode remains available; enforce the gate for any security claim and prohibit bypass at deployment.
2. File update and authority transaction are not atomic across process/power loss. A crash after the manifest replacement but before SQLite transaction completion may leave an effect with ambiguous authorization state; reconcile independently, never automatically replay.
3. A process outside this cooperating adapter can still modify the manifest; the fence is not an OS sandbox.
4. Identity is configured locally, not proved by an external identity provider or workload attestation.
5. No multi-host or remote downstream revocation; no distributed consensus or arbitrary side-effect containment.
6. Obtain independent adversarial review, additional fault injection, integrated deployment validation, and explicit release sign-off before considering production.

Do not merge as a production-ready security control solely because unit tests pass.
