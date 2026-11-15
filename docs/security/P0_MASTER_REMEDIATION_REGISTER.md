# P0 master remediation register

Decision: **NO-GO**. All 19 findings remain open against their complete requested acceptance criteria. No unit-level fix is counted as production closure. Owners below are required roles, not assigned people. Baseline: `f7bec6d599015a1f976fc85290868a3293c89ec4`, branch `fix/evidence-provenance-20261114`.

This review confirms specific defects and separately records missing guarantees. It does not assert that every hypothetical exploit has been reproduced. New tests reproduced ten baseline failures (one existing corruption control passed); missing evidence-table APIs are missing controls, not remote exploits. Code under `src/mcp_monitor/` is abbreviated below; test paths are under `tests/`.

| ID | Finding | Status | External acceptance blocker |
|---|---|---|---|
| P0-01 | Direct downstream bypass | PARTIAL | Deployment owner: provide host identity separation and private channel. |
| P0-02 | Non-bypassable authorization | PARTIAL | Gateway owner + deployment reviewer: test every reachable executable/channel. |
| P0-03 | Production identity | BLOCKED | Identity owner: approved disposable issuer and authenticated edge configuration. |
| P0-04 | Tenant isolation | PARTIAL | Tenant/resource owners: provision independent tenant resources and ACL sources. |
| P0-05 | Credential/session revocation | PARTIAL | Identity/SRE owner: live authoritative feed and agreed tested bound. |
| P0-06 | In-flight revocation | PARTIAL | Distributed systems owner: downstream fence support and partition testbed. |
| P0-07 | Consequence reconciliation | PARTIAL | Gateway owner: bind resource/preflight at reservation; provider owner: authoritative observation. |
| P0-08 | Duplicate execution | PARTIAL | Architecture owner: select shared authority and provider idempotency contract. |
| P0-09 | Runtime isolation | BLOCKED | Platform owner: disposable cluster and verified CNI. |
| P0-10 | Outbound network | PARTIAL | Network owner: enforce and test host/container packet boundary. |
| P0-11 | Split-brain safety | BLOCKED | Architecture owner: select distributed consistency/availability contract. |
| P0-12 | Authenticated transport | BLOCKED | Platform/identity owner: provision and test authenticated edge. |
| P0-13 | Crash durability | PARTIAL | SRE/storage owner: qualified durable volume and fault injection. |
| P0-14 | Operation-key custody | PARTIAL | Operations owner: protected issuance, no tombstone deletion, tested disaster recovery. |
| P0-15 | Observation consistency | PARTIAL | Provider/resource owner: define consistency and version API. |
| P0-16 | Secret exposure | PARTIAL | Security owner: private store/artifact scope and credential inventory. |
| P0-17 | Issuer revocation | BLOCKED | Credential owner: issuer access and explicit revocation authorization. |
| P0-18 | Deployment integrity | BLOCKED | Release owner: approved immutable artifact and signing/provenance review. |
| P0-19 | Independent acceptance | BLOCKED | Accountable human reviewer: approve exact tested RC only after all mandatory findings close. |

## P0-01 — Direct downstream bypass

- Root cause / failure scenario: Gateway enforcement cannot intercept another process or socket. Same-user direct execution remains possible.
- Affected code/configuration: `proxy/sandbox.py; proxy/protected_repo_sandbox.py; protected_repo_server.py`.
- Boundary / potential impact: Untrusted OS process → downstream/workspace. Direct invocation can modify files outside gateway policy.
- Existing controls and implementation: Pinned offline container; non-root, no host namespaces/runtime socket mounts. Explicit image source modes added.
- Missing controls / required architecture and implementation: Separate OS identities, gateway-only sockets/executables, hostile identity/process/filesystem/alternate-container tests on the actual host.
- Positive / negative / adversarial cases: Read an approved manifest; deny direct execution and verify manifest hash unchanged.
- Regression references: `test_phase14_bypass_matrix.py; test_phase14_isolated_docker.py`. Execution results, exact code SHA and CI URLs: [CI evidence](P0_CI_EVIDENCE.md). A reference alone is not a passing result.
- External acceptance dependency / owner: Deployment owner: provide host identity separation and private channel.
- Residual risk: acceptance remains open until the above deployment-level criteria pass. No VERIFIED FIXED claim.

## P0-02 — Non-bypassable authorization

- Root cause / failure scenario: Optional legacy library paths accept method passthrough; queued requests retained earlier approval.
- Affected code/configuration: `proxy/stdio_proxy.py; protocol/multiplex.py; policy/acl_guard.py`.
- Boundary / potential impact: Authenticated channel → dispatch. Revoked queued request could still invoke a tool.
- Existing controls and implementation: Strict method allowlist; policy and ACL checks. Added checks inside both send locks.
- Missing controls / required architecture and implementation: Full transport/resource inventory acceptance; restrict legacy entry points in deployed topology.
- Positive / negative / adversarial cases: Allow approved call; revoke while queued and assert downstream effect count zero.
- Regression references: `test_p0_security_boundaries.py::test_revocation_while_waiting_to_dispatch_has_zero_effects; test_hardened_tool_discovery.py`. Execution results, exact code SHA and CI URLs: [CI evidence](P0_CI_EVIDENCE.md). A reference alone is not a passing result.
- External acceptance dependency / owner: Gateway owner + deployment reviewer: test every reachable executable/channel.
- Residual risk: acceptance remains open until the above deployment-level criteria pass. No VERIFIED FIXED claim.

## P0-03 — Production identity

- Root cause / failure scenario: Offline trusted-key verification does not implement network OIDC onboarding or cryptographic client channel binding.
- Affected code/configuration: `proxy/oidc_identity.py; proxy/session_identity.py; production/server.py`.
- Boundary / potential impact: Client → identity authority. Stolen/unbound credentials or forged principal may be trusted by unsafe integration.
- Existing controls and implementation: Strict RS256 issuer/audience/tenant/session/time checks and callback; API-key HTTP inspection is separate.
- Missing controls / required architecture and implementation: Trusted issuer discovery/key refresh, authenticated channel binding and live two-tenant onboarding.
- Positive / negative / adversarial cases: Verify valid bound identity; reject forged/expired/tenant/session/key mismatches.
- Regression references: `test_phase7_oidc_identity.py; test_phase6_session_identity.py`. Execution results, exact code SHA and CI URLs: [CI evidence](P0_CI_EVIDENCE.md). A reference alone is not a passing result.
- External acceptance dependency / owner: Identity owner: approved disposable issuer and authenticated edge configuration.
- Residual risk: acceptance remains open until the above deployment-level criteria pass. No VERIFIED FIXED claim.

## P0-04 — Tenant isolation

- Root cause / failure scenario: Principal scoping exists; ownership/ACL provisioning for arbitrary resources and transports is operator dependent.
- Affected code/configuration: `proxy/session_identity.py; policy/acl_guard.py; proxy/stdio_proxy.py`.
- Boundary / potential impact: Tenant → resource/discovery/result. Cross-tenant disclosure under incomplete resource ownership configuration.
- Existing controls and implementation: Length-prefixed tenant principal; trusted resource ACL; request/result checks.
- Missing controls / required architecture and implementation: Authoritative resource tenant ownership and two independently configured deployed tenants.
- Positive / negative / adversarial cases: Tenant A allowed A; substituted B path denied with actual B state unchanged.
- Regression references: `test_step4_authoritative_acl.py; test_phase7_oidc_identity.py`. Execution results, exact code SHA and CI URLs: [CI evidence](P0_CI_EVIDENCE.md). A reference alone is not a passing result.
- External acceptance dependency / owner: Tenant/resource owners: provision independent tenant resources and ACL sources.
- Residual risk: acceptance remains open until the above deployment-level criteria pass. No VERIFIED FIXED claim.

## P0-05 — Credential/session revocation

- Root cause / failure scenario: Existing durable revocation only covered exact tenant/session/token triples; no issuer propagation integration.
- Affected code/configuration: `policy/durable_authority.py; proxy/oidc_identity.py`.
- Boundary / potential impact: Issuer/authority → sessions. New token for a revoked session could remain active.
- Existing controls and implementation: Added entire-session and token-wide revocations, tenant scoped; independent local readers see committed changes.
- Missing controls / required architecture and implementation: Live issuer feed, measured propagation bound, key rotation/outage tests across supported transports.
- Positive / negative / adversarial cases: Valid session active; all tokens of revoked session denied; other tenant unaffected.
- Regression references: `test_p0_security_boundaries.py::test_session_and_token_revocation_apply_to_independent_local_readers; test_phase8_durable_authority.py`. Execution results, exact code SHA and CI URLs: [CI evidence](P0_CI_EVIDENCE.md). A reference alone is not a passing result.
- External acceptance dependency / owner: Identity/SRE owner: live authoritative feed and agreed tested bound.
- Residual risk: acceptance remains open until the above deployment-level criteria pass. No VERIFIED FIXED claim.

## P0-06 — In-flight revocation

- Root cause / failure scenario: SQLite serializes cooperating local actors only; pre-send checks are not external commit fencing.
- Affected code/configuration: `protocol/revocation_fence.py; proxy/stdio_proxy.py; protocol/multiplex.py`.
- Boundary / potential impact: Authority → dispatch/commit. Stale workers may commit externally after revocation.
- Existing controls and implementation: Local file-commit lock, queued-dispatch rechecks; runtime authority-file substitution now denied.
- Missing controls / required architecture and implementation: Provider fencing/conditional commit and cross-host coordinator; define uninterruptible dispatch semantics.
- Positive / negative / adversarial cases: Effect before acknowledged revoke allowed; subsequent effects denied; tampered authority gives zero effects.
- Regression references: `test_phase16_revocation_safe_commit.py; test_phase16_crash_fencing_process.py; test_p0_security_boundaries.py`. Execution results, exact code SHA and CI URLs: [CI evidence](P0_CI_EVIDENCE.md). A reference alone is not a passing result.
- External acceptance dependency / owner: Distributed systems owner: downstream fence support and partition testbed.
- Residual risk: acceptance remains open until the above deployment-level criteria pass. No VERIFIED FIXED claim.

## P0-07 — Consequence reconciliation

- Root cause / failure scenario: Unverified public mark_completed method; observed evidence was discarded; mutable nested snapshot could alter comparison.
- Affected code/configuration: `protocol/effect_journal.py; protocol/consequence_verifier.py`.
- Boundary / potential impact: Untrusted acknowledgment → durable completion. False completion or unrelated edit accepted as expected effect.
- Existing controls and implementation: Removed unverified completion path; private exclusive store; snapshot copy; atomic observation evidence + completion; no replay.
- Missing controls / required architecture and implementation: Resource/preflight binding now persisted before dispatch and checked during reconciliation; provider observation adapters and distributed observation consistency still unavailable.
- Positive / negative / adversarial cases: Exact change stores provenance; false ACK, wrong arguments/unexpected change/evidence failure remain uncertain.
- Regression references: `test_p0_security_boundaries.py; test_phase15_consequence_verification.py`. Execution results, exact code SHA and CI URLs: [CI evidence](P0_CI_EVIDENCE.md). A reference alone is not a passing result.
- External acceptance dependency / owner: Gateway owner: bind resource/preflight at reservation; provider owner: authoritative observation.
- Residual risk: acceptance remains open until the above deployment-level criteria pass. No VERIFIED FIXED claim.

## P0-08 — Duplicate execution

- Root cause / failure scenario: Deduplication is a local SQLite reservation, not cross-host authoritative consensus.
- Affected code/configuration: `protocol/effect_journal.py; protocol/effect_authority.py`.
- Boundary / potential impact: Replay/concurrent worker → external effect. Independent databases or restored state permit duplicate dispatch.
- Existing controls and implementation: Atomic reservation, exact approved argument digest, all reuse denied, ambiguous stays uncertain.
- Missing controls / required architecture and implementation: Shared transactional coordinator, downstream idempotency/fence, partitions/failover acceptance.
- Positive / negative / adversarial cases: Single reservation wins; replay/conflicting key rejected without new effect.
- Regression references: `test_phase11_effect_journal.py; test_phase13_trusted_effect_approval.py`. Execution results, exact code SHA and CI URLs: [CI evidence](P0_CI_EVIDENCE.md). A reference alone is not a passing result.
- External acceptance dependency / owner: Architecture owner: select shared authority and provider idempotency contract.
- Residual risk: acceptance remains open until the above deployment-level criteria pass. No VERIFIED FIXED claim.

## P0-09 — Runtime isolation

- Root cause / failure scenario: Hardened YAML does not establish CNI enforcement or hostile identity containment.
- Affected code/configuration: `deploy/k8s/deployment.yaml; deploy/k8s/networkpolicy-deny-all.yaml; proxy/sandbox.py`.
- Boundary / potential impact: Container/pod → node/other workload. Lateral movement/direct downstream access if runtime differs.
- Existing controls and implementation: Non-root, capabilities dropped, seccomp, readonly root, no privilege escalation/SA token/host namespaces.
- Missing controls / required architecture and implementation: Actual cluster/CNI enforcement, lateral movement, socket/process/workspace tests.
- Positive / negative / adversarial cases: Approved channel works; namespace/socket/runtime/egress attacks fail before effects.
- Regression references: `test_deployment.py; test_phase5_docker_integration.py; test_phase9_internal_docker.py`. Execution results, exact code SHA and CI URLs: [CI evidence](P0_CI_EVIDENCE.md). A reference alone is not a passing result.
- External acceptance dependency / owner: Platform owner: disposable cluster and verified CNI.
- Residual risk: acceptance remains open until the above deployment-level criteria pass. No VERIFIED FIXED claim.

## P0-10 — Outbound network

- Root cause / failure scenario: Policy hints are not packet enforcement; webhook used proxy-aware redirect-following urllib.
- Affected code/configuration: `production/webhook_transport.py; production/alerting.py; proxy/internal_sandbox.py`.
- Boundary / potential impact: Gateway/server → network. Redirect, proxy or rebinding can expose internal endpoints or secrets.
- Existing controls and implementation: Webhook validates all DNS answers, pins sockaddr, requires verified HTTPS/public addresses:443, no redirects/proxies/retries; explicit local HTTP exception.
- Missing controls / required architecture and implementation: All process/transport egress enforcement, actual CNI, IPv6 and fault tests; sidecar policy not attested.
- Positive / negative / adversarial cases: Public mock accepted; private/metadata/IPv6 answers denied; local redirect target never contacted.
- Regression references: `test_p0_webhook_transport.py; test_phase9_internal_docker.py`. Execution results, exact code SHA and CI URLs: [CI evidence](P0_CI_EVIDENCE.md). A reference alone is not a passing result.
- External acceptance dependency / owner: Network owner: enforce and test host/container packet boundary.
- Residual risk: acceptance remains open until the above deployment-level criteria pass. No VERIFIED FIXED claim.

## P0-11 — Split-brain safety

- Root cause / failure scenario: Independent SQLite files have no global consensus, leader election or rollback-proof freshness.
- Affected code/configuration: `policy/durable_authority.py; protocol/effect_journal.py; protocol/revocation_fence.py`.
- Boundary / potential impact: Replica → authority. Stale partition can approve/replay operation.
- Existing controls and implementation: Local shared-file coordination and fail-closed unavailable store; cross-host mode unsupported.
- Missing controls / required architecture and implementation: Architecture decision, shared transactional/fenced service and partition/leader-failure tests.
- Positive / negative / adversarial cases: Shared local reader denies revoked grant; partitioned replica must fail closed in future testbed.
- Regression references: `test_phase8_durable_authority.py; test_phase11_effect_journal.py`. Execution results, exact code SHA and CI URLs: [CI evidence](P0_CI_EVIDENCE.md). A reference alone is not a passing result.
- External acceptance dependency / owner: Architecture owner: select distributed consistency/availability contract.
- Residual risk: acceptance remains open until the above deployment-level criteria pass. No VERIFIED FIXED claim.

## P0-12 — Authenticated transport

- Root cause / failure scenario: HTTP inspection has no native TLS/mTLS listener; stdio assumes trusted launcher.
- Affected code/configuration: `production/server.py; proxy/stdio_proxy.py; production/webhook_transport.py`.
- Boundary / potential impact: Network peer → channel identity. Plaintext/downgrade or peer substitution at unsafe edge.
- Existing controls and implementation: Outbound webhook system trust store/hostname verification; strict local stdio profile.
- Missing controls / required architecture and implementation: Inbound trusted TLS/mTLS termination and channel binding; rotation/expiration tests at the actual edge.
- Positive / negative / adversarial cases: TLS verification enabled; untrusted service peer must fail at deployment edge.
- Regression references: `test_p0_webhook_transport.py; test_phase7_oidc_identity.py`. Execution results, exact code SHA and CI URLs: [CI evidence](P0_CI_EVIDENCE.md). A reference alone is not a passing result.
- External acceptance dependency / owner: Platform/identity owner: provision and test authenticated edge.
- Residual risk: acceptance remains open until the above deployment-level criteria pass. No VERIFIED FIXED claim.

## P0-13 — Crash durability

- Root cause / failure scenario: WAL/FULL and process-kill tests do not prove hardware power-loss or external transactional atomicity.
- Affected code/configuration: `protocol/effect_journal.py; protocol/revocation_fence.py; protected_repo_server.py`.
- Boundary / potential impact: Storage failure → recovery. Lost intent or optimistic recovery could trigger unsafe replay.
- Existing controls and implementation: Intent durable before send; directory fsync at bootstrap; evidence atomic with completion; corruption unavailable/lock deny.
- Missing controls / required architecture and implementation: Power-loss/filesystem durability, storage exhaustion, corruption and external reconciliation acceptance.
- Positive / negative / adversarial cases: Crash retains uncertain reservation; missing/corrupt evidence cannot complete.
- Regression references: `test_phase16_crash_fencing_process.py; test_phase11_effect_journal.py; test_p0_security_boundaries.py`. Execution results, exact code SHA and CI URLs: [CI evidence](P0_CI_EVIDENCE.md). A reference alone is not a passing result.
- External acceptance dependency / owner: SRE/storage owner: qualified durable volume and fault injection.
- Residual risk: acceptance remains open until the above deployment-level criteria pass. No VERIFIED FIXED claim.

## P0-14 — Operation-key custody

- Root cause / failure scenario: Operator permits are in-process; retention/backup/failover custody not globally authoritative.
- Affected code/configuration: `protocol/effect_authority.py; protocol/effect_journal.py`.
- Boundary / potential impact: Client key → approved intent. Restored/pruned history or independent registry can repeat effect.
- Existing controls and implementation: Exact principal/server/tool/arguments permit; tenant-scoped principal; permanent local tombstones.
- Missing controls / required architecture and implementation: Durable issuance authority and antirollback retention/backup policy; global key namespace/failover tests.
- Positive / negative / adversarial cases: Permit exact match accepted; conflicting/restarted replay denied.
- Regression references: `test_phase13_trusted_effect_approval.py; test_phase11_effect_journal.py; test_p0_security_boundaries.py`. Execution results, exact code SHA and CI URLs: [CI evidence](P0_CI_EVIDENCE.md). A reference alone is not a passing result.
- External acceptance dependency / owner: Operations owner: protected issuance, no tombstone deletion, tested disaster recovery.
- Residual risk: acceptance remains open until the above deployment-level criteria pass. No VERIFIED FIXED claim.

## P0-15 — Observation consistency

- Root cause / failure scenario: A local file read is a point-in-time observation; reservation has no bound external version.
- Affected code/configuration: `protocol/consequence_verifier.py; protocol/effect_journal.py`.
- Boundary / potential impact: Observed state → completion claim. Concurrent change after inspection or wrong workspace misassociation.
- Existing controls and implementation: Exact semantic postcondition; before/observed hashes and timestamp/provenance stored; rejects unexpected change; FIFO read nonblocking.
- Missing controls / required architecture and implementation: Resource/preflight binding and current preflight check implemented; provider ETag/conditional verification and concurrent observation-to-commit fencing remain required.
- Positive / negative / adversarial cases: Exact transformation verified; unrelated edit/missing file denied; subsequent edits remain possible.
- Regression references: `test_phase15_consequence_verification.py; test_p0_security_boundaries.py`. Execution results, exact code SHA and CI URLs: [CI evidence](P0_CI_EVIDENCE.md). A reference alone is not a passing result.
- External acceptance dependency / owner: Provider/resource owner: define consistency and version API.
- Residual risk: acceptance remains open until the above deployment-level criteria pass. No VERIFIED FIXED claim.

## P0-16 — Secret exposure

- Root cause / failure scenario: Prior scanner skips based on nearby placeholder text and scans diffs rather than all blobs.
- Affected code/configuration: `scripts/p0_secret_scan.py; .github/workflows/security-hygiene.yml`.
- Boundary / potential impact: Repository/artifact → credential custody. Real token hidden beside EXAMPLE comment can evade scan.
- Existing controls and implementation: Added redacted tracked/full reachable blob scan with exact synthetic fingerprint exemption; branch CI enabled.
- Missing controls / required architecture and implementation: Private sources/secret stores/expired artifacts are not accessible; generic passwords and unsupported token formats remain outside detector.
- Positive / negative / adversarial cases: Nearby placeholder cannot suppress matching synthetic test token; known published AWS example precisely triaged.
- Regression references: `test_p0_secret_scan.py; tracked and reachable history scans`. Execution results, exact code SHA and CI URLs: [CI evidence](P0_CI_EVIDENCE.md). A reference alone is not a passing result.
- External acceptance dependency / owner: Security owner: private store/artifact scope and credential inventory.
- Residual risk: acceptance remains open until the above deployment-level criteria pass. No VERIFIED FIXED claim.

## P0-17 — Issuer revocation

- Root cause / failure scenario: Removing a demo value or denying its hash does not revoke it at an external issuer.
- Affected code/configuration: `production/config.py; SECURITY.md`.
- Boundary / potential impact: Exposed credential → issuer. A historically deployed credential may still authenticate.
- Existing controls and implementation: Known retired demonstration value rejected locally; no confirmed active issuer credential identified by bounded scan.
- Missing controls / required architecture and implementation: Authorized issuer inventory, approval to revoke/rotate, dependent update and old-token authentication rejection evidence.
- Positive / negative / adversarial cases: Local retired value denied; issuer negative authentication test pending.
- Regression references: `test_retired_demo_credential.py (local rejection only)`. Execution results, exact code SHA and CI URLs: [CI evidence](P0_CI_EVIDENCE.md). A reference alone is not a passing result.
- External acceptance dependency / owner: Credential owner: issuer access and explicit revocation authorization.
- Residual risk: acceptance remains open until the above deployment-level criteria pass. No VERIFIED FIXED claim.

## P0-18 — Deployment integrity

- Root cause / failure scenario: Kubernetes image digest intentionally invalid; default gateway base mutable; no approved artifact provenance.
- Affected code/configuration: `Dockerfile; Dockerfile.protected-mcp; deploy/k8s/deployment.yaml; .github/workflows/phase1-16-free-sbom-audit.yml`.
- Boundary / potential impact: Source/build → deployed artifact. Substituted or different artifact can evade tested controls.
- Existing controls and implementation: Protected image base pinned; explicit non-root source permissions; SBOM/dependency branch workflow enabled; missing build-test inputs copied.
- Missing controls / required architecture and implementation: Gateway base digest pinned to observed pulled manifest; image SBOM/licenses/provenance and rollback remain unverified. Optional builder-only trusted CA supports this environment without disabling verification.
- Positive / negative / adversarial cases: Trace exact built image IDs; smoke/rollback exact artifact; placeholder remains intentionally invalid.
- Regression references: `Docker builds; test_phase14_isolated_docker.py; SBOM and dependency scan`. Execution results, exact code SHA and CI URLs: [CI evidence](P0_CI_EVIDENCE.md). A reference alone is not a passing result.
- External acceptance dependency / owner: Release owner: approved immutable artifact and signing/provenance review.
- Residual risk: acceptance remains open until the above deployment-level criteria pass. No VERIFIED FIXED claim.

## P0-19 — Independent acceptance

- Root cause / failure scenario: Green CI and self-review cannot replace independent accountable acceptance.
- Affected code/configuration: `scripts/check_release_authorization.py; docs/security/P0_ACCEPTANCE.json; .github/workflows/release.yml`.
- Boundary / potential impact: Engineering evidence → release authority. Environment variables previously could approve despite open P0 register.
- Existing controls and implementation: Release now requires exact 19 records VERIFIED FIXED on matching SHA with evidence plus existing tag/SHA/human approval metadata. Repository decision NO-GO.
- Missing controls / required architecture and implementation: Independent reviewer, protected environment/tag controls, incident/rollback exercise and human exact-RC approval.
- Positive / negative / adversarial cases: Complete synthetic gate passes; open/missing/stale/evidenceless records denied.
- Regression references: `test_release_authorization.py; scripts/workflow_security_scan.py`. Execution results, exact code SHA and CI URLs: [CI evidence](P0_CI_EVIDENCE.md). A reference alone is not a passing result.
- External acceptance dependency / owner: Accountable human reviewer: approve exact tested RC only after all mandatory findings close.
- Residual risk: acceptance remains open until the above deployment-level criteria pass. No VERIFIED FIXED claim.

## Implementation provenance and observed validation

All implementation changes in this series are in commit `206f1955aabf6e7d5dc428e22f773fc4b35877ec`; exact changed paths are available in that commit. It passed [nine-job integrated CI](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43762146901), including the complete 1,305-pass/6-skip matrix on each supported Python version and the dedicated runtime fixtures. New adversarial tests live in `tests/test_p0_security_boundaries.py`, `tests/test_p0_webhook_transport.py`, `tests/test_p0_secret_scan.py` and `tests/test_release_authorization.py`; all are included in the full suite. No complete P0 closure follows from those results.

Second-pass remediation also binds workspace identity and preflight hash before dispatch, rejects stale preflight and unbound legacy reconciliation, sanitizes policy/detector exception contents, and separates development audit/WAL directories. Remaining provider/distributed observation semantics and hostile deployment acceptance stay open.

P0-18 has a concrete failing acceptance check, not merely missing evidence: the first exact runtime artifact produced 16 Critical and 139 High advisory matches. Follow-up removes unnecessary runtime curl/package installers and applies available distro updates, but unresolved base advisories still require exact-image verification and triage. No suppression, exception or production artifact approval is granted. Later commits also close the separately reproduced response-inspection log leak; their source and workflow provenance is appended in the CI record.
