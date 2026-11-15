# Phase 1–16 remediation and production acceptance tracker

**Decision: PRODUCTION NO-GO.** This is a tracked engineering backlog, not proof of release acceptance. Audit branch source baseline: `2158ab58e4a07a5c49b70c659996653a92f661c8`. This remediation branch is intentionally not merged to `main`.

## Latest independently observed CI snapshot (historical commit; not current head)

- Exact commit `463a85f85cdb0aa6a6e287ffba56c1b364cfcd31`: [integrated CI 43667123478](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43667123478) passed **5/5 jobs**, with **1,246 passed and 6 skipped per Python 3.10, 3.11, 3.12**; [poster parity 43667123466](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43667123466) passed on the same SHA.
- This documentation update is later than the verified commit and needs its own exact-head CI. Poster manifest remains intentionally frozen to the historical `a24f92c...` pair and does not prove current binary visual parity. The six skips and all independent production acceptance controls below remain open.

## Forty-two-item acceptance register (2026-11-15 UTC)

This register distinguishes implemented repository changes from independently verified production outcomes. **No item is accepted solely because a unit test passes.** All production promotion remains NO-GO.

| IDs | Required acceptance work | Current disposition |
|---|---|---|
| 1–2 | Non-bypassable downstream access and OS isolation; adversarial same-user/process/socket/workspace bypass tests | **BLOCKED**: deployment and hostile process boundary not available |
| 3–5 | Trusted IdP identity, tenant-scoped tool/resource authorization, real issuer revocation and in-flight fencing | **BLOCKED**: issuer, tenant integration and real credentials not available; local controls are not equivalent |
| 6 | Independently observe external provider effects, crash/lost-ack reconciliation, duplicate prevention | **BLOCKED**: provider-side idempotency and external ground truth not available |
| 7–8 | DNS/IPv4/IPv6/redirect/metadata/proxy egress isolation and production cluster validation | **BLOCKED**: target deployment and network policy enforcement not available |
| 9–12 | MCP transport/version compatibility, filesystem TOCTOU, tamper-resistant audit, external crash/retry fault injection | **PARTIAL**: repository tests exist; complete adversarial acceptance matrix not verified |
| 13–16 | Credential issuer/history audit, independent penetration test, threat/control traceability and failure injection | **BLOCKED/PARTIAL**: no issuer or independent tester; review does not imply exhaustive credential revocation |
| 17 | Verify pinned public manifest using Git blob hash rather than raw-file SHA-1 | **FIX COMMITTED**: integrated workflow changed; exact-head pass pending |
| 18–19 | All exact-head jobs green, dedicated opt-in integration tests executed without skips | **PARTIAL**: dedicated Phase 5/9/14/official filesystem jobs passed at prior head; public manifest failed and matrix not green |
| 20–24 | Branch/line coverage, manifest/job/log provenance, representative attacks, false positives, comprehensive CI triggers | **PARTIAL**: CI log reconciliation implemented; full metrics and independent benchmark pending |
| 25–27 | Current poster PDF/PNG reconciliation, deterministic rendering and human print-readability inspection | **OPEN**: exact-byte comparison correctly detects committed PDF mismatch; visual review and reproducible render pending |
| 28–29 | Historical vs current metrics and documentation consistency | **PARTIAL**: main banners updated; remaining historical tracker passages need resolution annotations |
| 30–33 | Authentic SBOM, immutable release digest, protected approvals, live rollback rehearsal, safe branch/PR reconciliation | **OPEN**: no release authorization or deployment proof |
| 34–42 | Competitor baseline, controlled adversarial comparisons, ground truth, ablations, latency/false-positive measurements, reproducible novelty package | **NOT ESTABLISHED**: uniqueness cannot be asserted before comparative evidence |

**Adversarial acceptance questions:** Can a client reach downstream without gateway authorization? Can a revoked principal obtain an already-computed response? Can a timeout cause a duplicated external action? Can a local adversary replace a checked file before use? Can DNS, IPv6, redirects or proxies bypass egress policy? Can audit records be deleted or forked without independent detection? Can a green CI run be paired with stale poster binaries or fabricated counts? Can competing gateways match the purported novelty under the same tests? Each question requires an observed pass/fail result and preserved evidence, not a narrative assertion.

**Release gate:** keep the PR in draft and production NO-GO until every required control is implemented, tested on the exact promoted SHA, independently reviewed and explicitly approved. Do not use provider API keys or paid services to fabricate validation.

## Current implementation evidence updates (2026-11-15 UTC)

- **Item 17 — verified on historical exact SHA:** [integrated run 43674537092](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43674537092), pinned public manifest job **success**, Git blob hash verification and actual gateway test **1 passed**. This corrects the previously erroneous raw SHA-1 comparison; later commits need their own CI.
- **Items 18–19 — partial:** Phase 5, Phase 9 and Phase 14 disposable Docker jobs succeeded on the above run. Generic matrix still intentionally skips fixture-gated cases; accept only with explicit same-SHA dedicated successes. Do not claim all acceptance jobs green until run conclusion is successful.
- **Item 20 — implementation committed, validation pending:** integrated regression now requests line and branch coverage, publishes per-version `coverage.xml` artifacts. No numerical coverage claims until the new job completes.
- **Items 25–27 — unresolved, evidence preservation improved:** poster workflow retains newly rendered PDF/PNG on parity failure. Exact-byte parity still fails against committed poster. A reviewer must compare visual differences and determine whether deterministic reproduction is achievable; preserving an artifact is not the same as accepting it.
- **Items 1–16 and 21–42:** the 42-point register above remains authoritative; no additional production or novelty claims were established by these CI improvements.

## Audit remediation status — 2026-11-15 UTC (commit-specific)

- **Coverage artifact:** integrated workflow now sets `if-no-files-found: error` for `coverage.xml` on each Python matrix job. This closes a missing-artifact silent-warning gap, but does **not** set a coverage threshold or establish a current coverage percentage.
- **Poster:** exact-byte comparison remains a blocking failure, with generated artifacts retained for investigation. A comment documents that nondeterministic PDF metadata must not be silently ignored. **The binary mismatch is not fixed.**
- **Deployment:** the intentionally invalid image digest is a deliberate release safety gate. A verified published digest and authorized cluster test are required; replacing the placeholder with a guessed digest would create a vulnerability.
- **Network policy:** deny-all configuration and structural test exist, but no live CNI enforcement or authorized exceptions have been validated.
- **Credential audit:** a fixed release-test key was replaced with per-run random material; no provider-side revocation or full historical secret scan has been established.
- **Document review:** prior file inventory and selected-line inspections are **not** a completed 333-file line-by-line audit. Do not describe the entire repository as reviewed.
- **Release:** keep PR in draft and production **NO-GO** pending exact-head CI, poster reconciliation, deployed security controls and independent review.

## Verified observations

- Historical integrated five-job run [43657894182](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43657894182) passed at audit SHA `2158ab58e4a07a5c49b70c659996653a92f661c8`, with 1,245 passed and 6 skipped per Python version. This is **not** a validation of the remediation head.
- Poster provenance workflow [43661291942](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43661291942) succeeded at `96ed7d1b61815e40da37103f6bbd3a36721796c9`.
- Correct historical same-source poster and integrated pair: runs 43657370960 and 43657370973 at `a24f92c17f93d5c150eafe4ba7dce507ecb534b6`. The manifest validates run status, workflow identity and SHA; it does not independently establish every numeric claim from the job logs.
- Any subsequent remediation head must pass its own five-job integrated matrix and poster rendering before merge. Six skips require explicit review.

## Critical unresolved engineering controls

| Control | Required independent acceptance evidence | Status |
|---|---|---|
| Non-bypassable routing | Deny same-user direct MCP server invocation, direct process/socket/volume access, and untrusted Docker daemon control in the **actual deployment**; red-team attempts must fail without reliance on cooperative clients | NOT VERIFIED |
| External identity and revocation | Real IdP-bound client identity, tenant authorization, key rotation, revoked token and concurrent in-flight operation tests on all transports | NOT VERIFIED |
| Outbound access | Deny unauthorized IP/DNS/IPv6/redirect/proxy/metadata egress in network-enabled deployment, with packet-level observations | NOT VERIFIED |
| Durable consequences | Real external provider idempotency, reconciliation of timeout/lost acknowledgments, restart and crash cases with independently observed state | NOT VERIFIED |
| MCP interoperability | Frozen protocol/version/transport matrix including unsupported methods, notifications, cancellation and malformed frames | NOT VERIFIED |
| Adversarial benchmarking | Independent blinded cases, source provenance, false-positive cost, attack adaptations and predeclared thresholds | NOT VERIFIED |
| Credential lifecycle | Issuer-side inventory and rotation/revocation records, secret-store and historical exposure assessment | NOT VERIFIED |
| Release authorization | Exact promoted SHA, protected release environment and tags, independent reviewer approval and signed residual-risk acceptance | NOT VERIFIED |

## Merge and branch policy

- Do not delete `integration/phase1-16-verified`, `security/phase1-16-audit` or this remediation branch until PRs and unique commits are reviewed.
- At review time the remediation branch was 417 commits ahead of `main`, 0 behind, and 33 ahead of the integration branch. These are comparison counts, not proof that every commit is appropriate for `main`.
- Prefer reviewable staged integration, branch protection and exact-head CI over an unreviewed 400+ commit merge.
- Generated poster PDFs/PNGs from Actions must be visually inspected; passing automated text/page checks does not certify print readiness.

## Release rule

No production claim, release tag or deletion of provenance branches until every applicable control has independent evidence and accountable human GO. A passing test workflow cannot override this NO-GO.

## Devil's-advocate source audit (2026-11-14 / November 15 UTC)

The repository tree API returned 378 entries without truncation. This is a **repository-wide inventory and targeted source review**, not a line-by-line security certification of every file. Review depth is tracked explicitly.

| Surface | Reviewed files / observations | Finding and disposition |
|---|---|---|
| Release automation | `.github/workflows/release.yml`, `scripts/check_release_authorization.py` | **HIGH:** A missing `requirements.txt` previously led to a fabricated empty source SBOM; the fallback was removed. A mutable GHCR `:latest` tag was also removed. Still needs tag protection, independent approval and release rehearsal. |
| CI and evidence | `.github/workflows/phase1-16-integrated-security.yml`, `.github/workflows/poster-artifact-parity.yml`, `poster/evidence_manifest.json`, poster claims | Historical SHA mismatch corrected. Provenance now checks GitHub run identity, success and matching SHA; numeric totals are not independently extracted from run logs by this check. |
| Protected server | `src/mcp_monitor/protected_repo_server.py`, `src/mcp_monitor/proxy/protected_repo_sandbox.py` | **CRITICAL boundary:** approved local file effects can still be reached by a principal with direct downstream process/workspace access. A cooperative fence is not OS-enforced non-bypassability. Workspace path and inode checks are not proof against hostile concurrent filesystem modification. |
| Revocation and consequence | `src/mcp_monitor/protocol/revocation_fence.py`, `src/mcp_monitor/protocol/consequence_verifier.py` | Cooperative single-authority SQLite revocation and local manifest observation; not a remote IdP, distributed fencing or independently verified external outcome. |
| Production HTTP | `src/mcp_monitor/production/server.py`, `src/mcp_monitor/production/config.py` | HTTP operator API keys and request framing have implementation paths; no demonstrated production tenant identity binding or deployment-specific TLS/egress controls. |
| Kubernetes and Compose | `deploy/k8s/deployment.yaml`, `deploy/k8s/service.yaml`, `deploy/k8s/secret.example.yaml`, `docker-compose.yml` | **HIGH:** Kubernetes example uses a mutable version tag rather than a digest; service is plaintext inside cluster with TLS delegated externally. No evidence of live mTLS, NetworkPolicy, or restricted workload access. Do not promote this manifest as-is. |
| Test suite | `tests/` inventory and full integrated GitHub workflow | Prior 1,245-pass, 6-skip run is exact-SHA evidence only. Newly triggered runs and skipped-test explanations require inspection. |
| Poster and documents | `poster/render_poster.py`, research brief, metrics, ledger, README, PRODUCTION | Source/parity check does not prove print readability or effectiveness claims; committed PDF/PNG may be historical. |

### Post-mortem: cause, impact, prevention

1. **Cause:** Evidence was duplicated in Markdown and workflow literals. **Impact:** Successful historical runs were cited with mismatched SHAs, and changes could break CI or preserve stale claims. **Prevention:** Single evidence manifest, API-backed run/SHA validation and explicit historical/current separation.
2. **Cause:** Release workflow treated missing source dependency input as a zero-dependency project. **Impact:** An empty source SBOM could falsely suggest completeness. **Prevention:** Remove fallback; require genuine source-lock provenance before source-SBOM claims.
3. **Cause:** Runtime image publishing used a mutable alias. **Impact:** Tag contents could change without changing deployment references. **Prevention:** Publish version tags only; require immutable digest pinning for actual deployment.
4. **Cause:** CI trigger list excluded remediation branch. **Impact:** Docs/workflow fixes could be merged without the integrated matrix on the proposed head. **Prevention:** Include remediation branch and report skip reasons with `pytest -rs`.
5. **Cause:** The prototype's control plane and enforcement perimeter are different. **Impact:** Tests of the gateway do not rule out direct invocation of a downstream server. **Prevention:** Host/namespace/network isolation and independent adversarial bypass tests.

### Premortem: likely next failure modes

- A successful workflow at an older commit is mistaken for validation of the new release head.
- A deployer copies the Kubernetes example with a mutable image tag and no enforced network isolation.
- An untrusted process bypasses the proxy and reaches the protected server or shared manifest directly.
- A remote operation times out after succeeding, then gets retried without provider-side idempotency.
- A legitimate release is blocked by missing human approvals, or a release administrator weakens the environment controls to get a green check.
- The poster artifact is circulated from the committed binary instead of the verified current render.

**Audit limitations:** No production cluster, IdP, credential issuer, third-party provider, real external consequence, independent tester, or full local file-by-file static analysis was accessed in this review. Do not infer absence of vulnerabilities from the inventory or from passing CI.

## Follow-up remediation and test review

- The exact-head integrated run [43661565902](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43661565902) passed all five jobs at `956d4a7b8b10f590ec0c871e14fcfaf95596db95`. Python 3.12 logs show **1,245 passed / 6 skipped**. This does **not** validate later Kubernetes manifest or documentation changes.
- The six reported skips are: `test_first_party_public_manifest.py` (pinned public manifest not fetched); `test_live_filesystem_mcp.py` (real server opt-in / Node); two `test_phase14_isolated_docker.py` cases (pinned local Docker image missing); `test_phase5_docker_integration.py` (Phase 5 image ID absent); and `test_phase9_internal_docker.py` (Phase 9 fixture not provisioned in the general pytest job). Separate Docker workflow success is not equivalent to unskipping every test in the full matrix.
- The Kubernetes Deployment now contains an **intentionally invalid** immutable-digest placeholder. This prevents accidental tag-based promotion but is not a deployable manifest. Only an independently verified 64-character image digest and explicit deployment approval can replace it. Documentation includes the prerequisite warning.
- The release workflow no longer publishes a mutable `:latest` alias or invents a zero-dependency source SBOM. A genuine source-specific dependency SBOM remains **outstanding**, not certified.
- The remaining high-risk controls (downstream bypass, remote identity/revocation, network egress, provider effects, release environment rules, independent testing) remain **unresolved** and must not be reclassified as fixed merely because the workflow passes.


## November 15 follow-up — verified results and unresolved exact-head parity

- Three regenerated poster binaries were committed by the reviewed one-time workflow at `f1b8ee9574ed33683ab4149bb797ac45e97d090e`; the temporary write-enabled workflow was subsequently deleted.
- Integrated security candidate run [43744627479](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43744627479) completed successfully with nine jobs, including real Docker isolation and official MCP filesystem integration. This is CI-scoped, not production deployment approval.
- Poster Artifact Parity [43744455052](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43744455052) passed at an earlier branch commit. Later [43744822263](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43744822263) failed: PDF extracted text and PNG visible pixels matched, but PDF raster pixels differed at 0.5x. Thus exact-head visual reproducibility is intermittent; do not represent poster parity as permanently resolved.
- The workflow now rejects PDF text, dimensions, and raster changes and PNG pixel changes. Browser/runtime font and rendering nondeterminism must be investigated and pinned before merging. No parity gate should be removed solely to obtain a green run.
- Production **NO-GO** remains in force. No independently verified production Kubernetes CNI network-policy enforcement, issuer-side credential revocation, cross-tenant authorization across all entry points, or external side-effect reconciliation has been demonstrated.
- Recruiter-facing metrics must distinguish the historical October 782 tests / 81.93% coverage from the November nine-job integrated validation. Neither is a claim of deployed production security.
