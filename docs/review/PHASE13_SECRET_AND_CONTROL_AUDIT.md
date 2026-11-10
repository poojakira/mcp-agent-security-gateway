# Phase 13: credential exposure review and production-control evidence

> **Integration-documentation review (2026-11-09):** Retiring a known demonstration credential in source is different from confirming live credential rotation at its issuer; historic searches are not a comprehensive secret inventory. The development integration is [draft PR #167](https://github.com/poojakira/mcp-agent-security-gateway/pull/167), **not a production-approved release**.
**Decision: production NO-GO.** This is a source-level review and scoped, free CI exercise, not an incident closure, provider revocation certificate, penetration test or deployment authorization. Treat exposed candidate credentials as compromised until independently verified. Never publish actual credential values in reports or CI logs.

## Secret exposure review

- The authenticated GitHub account exposes 21 accessible repositories (15 public, 6 private) during this review. Credential-pattern searches were run across their **indexed default-branch source** for AWS key prefixes, GitHub tokens, OpenAI-style keys, Google API keys, private-key delimiters, API-key/secret/password references and similar terms. The results mostly point to regexes, tests, synthetic red-team payloads, configuration reading environment variables, and documentation. **No real, valid cloud/API-provider credential was confirmed in these sampled matches.** This is not an exhaustive byte-level scan of every commit, binary, pull-request artifact, Actions log or non-indexed branch, and presence/absence of a search match does not establish credential validity.
- **Confirmed exposure of a reusable local gateway demonstration credential:** the public default branch's `docker-compose.detection-lab.yml` includes a fixed demonstration `MCP_API_KEY`. It is a known public value regardless of whether anyone deployed it. It **must never authenticate a deployed gateway**.
- The standalone unmerged security PR #150 replaces that fixed value with a required operator-generated environment variable and binds lab ports to loopback. Both corrected files were copied into the stacked Phase 13 draft PR #159. Source remediation is not live revocation.
- The Phase 13 branch further rejects the **SHA-256 fingerprint of that previously published demonstration credential** during `Config` initialization, including the multi-key list. The actual old credential is not reproduced in the denylist source code; negative tests construct the publicly known string solely as a synthetic regression. This only takes effect when updated code is deployed. The standalone lab still disables Elasticsearch/Kibana authentication; it is restricted to local use.
- GitHub token-looking strings in red-team test content, AWS `EXAMPLE` test patterns, and scanner regexes require context checking; none of the inspected examples proved live credential ownership. These are not grounds to invoke provider revocation or claim an account was compromised.
- **Not performed:** provider-side revocation (no identified provider token or authorized provider key-management endpoint), rotation in existing running deployments, inspection of operator secret stores / GitHub Actions secret values, live infrastructure inventory, full historical scan of all 21 repositories, or verification of previous use from authentication logs.

## Emergency operational actions for actual deployed instances (operator required)

1. **Immediately isolate** any service accepting the known public gateway demonstration key. Roll out a new, unique high-entropy key from an appropriately managed secret store; remove the old key from every allowed credential list, restart/roll the running instances, and test that the old credential is rejected (without logging its bytes).
2. If an actual cloud/vendor token is subsequently confirmed, revoke or disable it at the **issuing provider** and generate a new least-privilege token. Check activity logs and audit access during its exposure window, and rotate dependent secrets if required. Editing a GitHub file or rewriting Git history does **not** revoke a credential.
3. Do not deploy the unsecured default-branch detection lab or expose the unauthenticated Elasticsearch/Kibana lab to other hosts. Treat PR #150 as high-priority security remediation requiring review and verified rollout; do not merge Phase 5–13 experimental stacks as a shortcut.
4. Search local/CI/deployment configuration, secret stores, artifacts, logs, and historical branches with a vetted secret scanner under operator-controlled access. Suppress printing of raw values. Preserve incident evidence and record provider revocation confirmation when available.

## Six requested production controls

| ID | Implemented/proved in source | Production gap; acceptance needed |
|---|---|---|
| 1. Identity, authorization and revocation | Phase 6 signed local session, Phase 7 pinned offline RS256 JWKS and revocation callback, Phase 8 signed same-host SQLite authority/ACL. Tests for signature/tenant mismatch and response suppression. | No externally authenticated OIDC login or trusted transport, remote durable revocation with restart rollback anchor, verified multi-host freshness, enforced client-to-gateway ingress or proof against bypassing the gateway. **OPEN** |
| 2. Secure outbound access | Phase 5 opt-in `--network=none` Docker isolation and Phase 9 internal-only Docker bridge with synthetic sidecar and startup attestation. | Sidecar is not an outbound CONNECT proxy; no live destination/port/redirect/DNS rebinding controls, topology drift monitor or representative egress verification. **OPEN** |
| 3. Crash recovery and effects | Phase 11 SQLite intent reservation before forwarding, no automatic retry on unknown outcomes and duplicate-key denial in same-host tests. | No trustworthy operator reconciliation of UNCERTAIN outcomes, durable operation-key authority, crash/power-loss testing, cross-host coordination or downstream exactly-once assurance. **OPEN** |
| 4. MCP interoperability | Phase 10 bounded stdio multiplexing, request ID/timeout/cancellation tests; real pinned filesystem MCP server smoke test exists separately. | No full Streamable HTTP / SSE support, no server-originated request handling, progress streaming or broad client/server compatibility matrix. Cancellation cannot undo tool side effects. **OPEN** |
| 5. Independent evaluation | Phase 12 frozen 96 author-curated regex-only cases: TP=40, FN=8, FP=16, TN=32; reproducible CI. | No independent annotations, blind representative data or full gateway attack-chain evaluation. Do not interpret the 16/48 benign false alarms or 8/48 missed malicious cases as production rates. **OPEN** |
| 6. Integrated deployment/release | Phase 13 lab configuration static gate and full Python 3.10–3.12 regression suites; isolated historical Docker/real-filesystem tests. | No final approved integrated release commit, deployment with authenticated identity and network controls, real crash recovery, supply-chain review and operator signoff. **OPEN** |

## Evidence boundaries

- [Phase 7 identity and revocation](PHASE7_OIDC_JWKS_PILOT.md); [Phase 8 local authority](PHASE8_DURABLE_AUTHORITY.md)
- [Phase 9 internal network](PHASE9_INTERNAL_NETWORK_PILOT.md); [Phase 10 multiplex](PHASE10_MULTIPLEX_PILOT.md)
- [Phase 11 intent journal](PHASE11_EFFECT_JOURNAL.md); [Phase 12 frozen benchmark](PHASE12_BENCHMARK_PROTOCOL.md)
- [Phase 13 acceptance checklist](PHASE13_RELEASE_READINESS.md); [controlled real filesystem smoke](../../tests/test_live_filesystem_mcp.py)
- [PR #150](https://github.com/poojakira/mcp-agent-security-gateway/pull/150); [Phase 13 draft PR #159](https://github.com/poojakira/mcp-agent-security-gateway/pull/159)

**Disposition:** The known local demo credential is source-retired on an unmerged draft branch and rejected by the proposed updated configuration parser. **Actual deployment rotation/provider-side revocation remains unverified.** None of the six production areas is certified; preserve NO-GO status and keep PR experimental.
