> **Evidence reconciliation (2026-11-11; historical phase/snapshot):** Historical results below retain their original dates and denominators. Latest tested Phase 1–16 development SHA is `43a72c8984bf9a472b9055d4f9e84cc759f61718` ([CI](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42971171992): 1,211 passed, 6 skipped per Python version), **not** a merged or production-approved release. Offline research tests require no paid provider or provider-issued API keys; deployed HTTP authentication and unverified real credential revocation remain separate. See [operating restrictions](../../PRODUCTION.md) and [release evidence](../../docs/review/PHASE1_16_RELEASE_CANDIDATE_NO_GO_20261110.md).

# Phase 13 — adversarial hardening status and acceptance boundary

> **Integration-documentation review (2026-11-09):** The historical hardening milestone and draft source changes cannot by themselves close the integrated release gate or establish real provider-side credential revocation. The development integration is [draft PR #167](https://github.com/poojakira/mcp-agent-security-gateway/pull/167), **not a production-approved release**.
**Decision:** Production NO-GO. This is an isolated, free, credential-free research/development branch, **not** a release authorization. The branch is intentionally draft and unmerged.

## Emergency fix on main

- PR [#150](https://github.com/poojakira/mcp-agent-security-gateway/pull/150) was reviewed and merged to `main` as squash commit `7aad3aa1e641799382903c61febdd44210d715c2`.
- The public detection-lab Compose file no longer contains the known demo credential and now requires an operator-supplied value; gateway, Elasticsearch and Kibana lab published ports bind to loopback.
- The updated production configuration rejects the known retired demo credential fingerprint. The exposed value remains in historical Git commits.
- **No live credential was accessed, used, rotated or provider-revoked in this work.** An already-running gateway must be isolated, updated/recreated, and independently verified to reject the retired key. Public source edits are not proof of deployment revocation.

## Controls implemented on the Phase 13 development branch

| Scope | Implemented defensive change | Evidence / limitation |
|---|---|---|
| Tool capability | Optional `PolicyEngine.allowed_tools` exact-name allowlist; denies unlisted tools with a structured reason | Enforced in hardened CLI; legacy library constructors can still opt out, so not universal |
| Secure startup | CLI requires `--allow-tool` plus offline/internal Docker isolation, or an explicit `--unsafe-local-dev` flag | Explicit unsafe flag remains possible for local disposable tests; it is not a production profile |
| MCP method boundary | Hardened CLI rejects unapproved non-tool methods (including resources/read and prompts/get), preventing unsupported passthrough of those paths | Complete MCP interoperability intentionally not claimed; optional direct library mode remains less restrictive |
| Stdio concurrency | Serialize non-multiplexed exchanges to prevent response cross-delivery under concurrent calls | Dedicated concurrency regression added; multiplexed mode has its own reader/ID correlation |
| Subprocess availability | Discard untrusted child stderr to avoid an undrained pipe deadlock; test a >2 MiB stderr flood | Diagnostic stderr is discarded, not logged; a safe bounded stderr capture would require separate design |
| Audit continuity | fsync audit append, update in-memory chain only after successful persistence, latch unhealthy on write failure, verify existing chain at startup | Bare SHA-256 is still forgeable by someone who can rewrite the full file; production must provision protected HMAC signing keys or external append-only assurance |
| Egress intent | Missing/expired correlation fails closed in the optional recipient heuristic | Does not inspect arbitrary outbound bytes or guarantee real network enforcement; the agent's recipients are not authoritative user consent |
| Supply chain | Added Bandit, public `pip-audit`, and CycloneDX SBOM generation in free CI; upgraded CycloneDX and patched lxml requirement after CVE/PYSEC finding | Vulnerability assessment covers CI-installed dependencies; runtime image scanning and attestation remain separate |

## Non-negotiable remaining release blockers

1. **Universal PEP:** prove every supported MCP client/transport must traverse the same authenticated enforcement point, with no direct downstream server access. The HTTP inspection API is **not** inline MCP forwarding.
2. **Identity & distributed revocation:** trusted identity acquisition, per-tenant binding and role/resource authorization, reliable revocation across hosts/restarts, enforcement prior to side effects.
3. **True network egress:** OS/container isolation of all downstream processes, DNS resolution and rebinding controls, proxy-only sockets, redirect/host/IP/port rules, lifecycle monitoring.
4. **Effect recovery:** trusted operation identifiers, dispatch/ack and unknown-effect reconciliation across crashes; no exactly-once/rollback promise.
5. **Transport compatibility:** broader official MCP method/notification/cancellation/streamable HTTP matrices and adversarial multi-client interleaving.
6. **Independent security evidence:** blinded, representative, rights-cleared testing of injection, data exfiltration, false alarms and bypass; 96 author-curated regex-only cases are not field efficacy.
7. **Supply-chain and release:** verified runtime image and OS package scans, SBOM provenance, cluster hardening, incident rollback, explicit review and human authorization.
8. **Branch convergence:** review the divergence among phase 13 PR #159, protected MCP PR #160 and earlier stacked branches before any release merge.

## No API key usage in hardening

The hardening tests are synthetic and use no real provider API keys. The repository's existing HTTP inspection service may require operator-provided authentication credentials in an actual deployment; this development change neither creates nor retrieves those credentials. No paid services or real customer systems were used.

## Decision

- **Emergency main-branch credential source fix: merged and verified.**
- **Phase 13 development hardening: changes under CI and review.**
- **Phase 13 production gate: remains NO-GO.**
- **Dependent Phase 14 production work: must not claim Phase 13 as approved.**

Keep the draft review explicit about unresolved controls, rather than converting green unit tests into a production-security certificate.
