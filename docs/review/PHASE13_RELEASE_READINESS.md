# Phase 13 — Integrated security and release-readiness gate

**Current decision: NO-GO for production.** This is a release gate and an evidence ledger, not a deployment authorization. The document is initially based on the Phase 12 stacked head cfd42b8df5561e0b6ea4dd1ed75281abc9e84a95. Update this verdict only after testing the *final integrated source commit*.

## Scope and evidence boundaries

Phases 5–12 are scoped, opt-in pilots with isolated or stacked draft pull requests. Their green CI runs establish only the tests described in those phase records, not deployment security, continuous controls, or full product support. Phase 12 used 96 author-curated synthetic cases and the regex detector only, with TP 40, FN 8, FP 16 and TN 32. Those rates must not be presented as field efficacy. Phase 13 must not simply add up earlier green tests.

## Release blockers (all require evidence on one integrated commit)

| ID | Risk and acceptance criterion | Current state |
|---|---|---|
| P13-01 | Integrate and review all applicable stacked PRs #148, #149, #151–#158 and independently apply/reconcile the distinct security fix #150. Resolve divergent configuration and keep recorded SHA evidence. | BLOCKED: all are unmerged |
| P13-02 | Detection-lab Compose must require a fresh operator-supplied secret and bind every published lab port to 127.0.0.1. Actual reused keys must be rotated/revoked in the systems where they were used; source editing is insufficient. | BLOCKED: Phase 12 inherited a fixed public demo key and unrestricted port bindings; PR #150 addresses source configuration only and is unmerged |
| P13-03 | Enforce identity and tenant-scoped authorization across supported MCP methods, tool arguments, responses, revocations, concurrent requests and restarts. Prove clients cannot bypass the gateway through alternate direct tool-server connections in the intended deployment. | OPEN: local identity/JWKS and durable authority pilots only |
| P13-04 | Real, restricted outbound network functionality must demonstrate strict host/IP/port/DNS/redirect controls. Monitor Docker network membership drift and verify full lifecycle cleanup under real failure. | OPEN: Phase 9 sidecar never forwards external traffic |
| P13-05 | Distinguish dispatch, unknown outcome and confirmed effect. Document trusted stable operation-key issuance, durable journal custody, crash/power-loss test results and operator reconciliation. No exactly-once or rollback claims. | OPEN: Phase 11 same-host pilot |
| P13-06 | Document exact supported MCP protocol/transport matrix. Test client and server versions, concurrency, cancellation, notifications and unexpected server messages; unsupported paths must fail closed or be explicitly blocked. | OPEN: Phase 10 is bounded stdio pilot, not complete MCP/Streamable HTTP |
| P13-07 | Evaluate the combined enforcement path using independent or blind, legally sourced, de-identified real-world-like fixtures and a justified benign/malicious sampling policy. Report bypasses, false positives, impact and confidence intervals separately. | OPEN: Phase 12 author-curated synthetic regex-only baseline |
| P13-08 | Execute end-to-end tests with real, disposable MCP servers and clients including deny-before-side-effect, post-revocation races, malformed downstream behavior, retries, authentication failures, resource limits, isolation and audit event continuity. | OPEN: earlier phase-specific tests do not establish integrated release readiness |
| P13-09 | Perform dependency/image provenance, SBOM, license, secret scanning, container hardening, default-config review, audit-event tamper/failure handling and threat-model review. Record residual risks and owners. | OPEN: consolidated production review not yet verified |
| P13-10 | Require reviewed release manifest: exact integrated commit and CI run links, supported configurations, known limitations, rollback/incident instructions, and explicit human release authorization. | OPEN: no approved production release |

## Automated first gate

The Phase 13 test reads only docker-compose.detection-lab.yml and checks:
1. Each port exposed by mcp-gateway, elasticsearch and kibana uses a 127.0.0.1 host binding.
2. MCP_API_KEY is mandatory, requires an operator-provided value, and cannot silently use a fixed default.
3. The previously published demonstration credential does not occur in the active lab Compose text.

The test is intentionally red on the inherited Phase 12 branch. A red job here is the correct *NO-GO* outcome, not evidence that earlier phase tests regressed. It should turn green only after the separate PR #150 fix is reconciled into the release candidate and the exact integrated commit is tested.

**This narrow static gate does not scan all secrets, revoke credentials, validate runtime host exposure, or prove production safety.** Keep the PR draft and do not merge, publish or deploy based on its eventual green status alone.

## Free and safe validation policy

Use only free public-repository GitHub Actions, local synthetic fixtures and disposable offline Docker targets. No paid services, real customer information, outside-system attack traffic, live provider accounts, or production deployment. Review evidence and blockers before expanding scope.

## Exit criteria

- Every P13-01 through P13-10 criterion has a dated evidence link or a written exception approved by an accountable reviewer (no exception for open critical exploitable findings).
- A single integrated release-candidate commit passes the relevant full regression and controlled security verification suites.
- The release remains NO-GO until all mandatory security gates are closed and explicit deployment approval is obtained.
