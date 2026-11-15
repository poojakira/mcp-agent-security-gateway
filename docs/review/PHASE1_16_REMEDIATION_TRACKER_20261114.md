# Phase 1–16 remediation and production acceptance tracker

**Decision: PRODUCTION NO-GO.** This is a tracked engineering backlog, not proof of release acceptance. Audit branch source baseline: `2158ab58e4a07a5c49b70c659996653a92f661c8`. This remediation branch is intentionally not merged to `main`.

## Verified observations

- Historical integrated five-job run [43657894182](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43657894182) passed at audit SHA `2158ab58e4a07a5c49b70c659996653a92f661c8`, with 1,245 passed and 6 skipped per Python version. This is **not** a validation of the remediation head.
- Poster provenance workflow [43661291942](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43661291942) succeeded at `96ed7d1b61815e40da37103f6bbd3a36721796c9`.
- Correct historical same-source poster and integrated pair: runs 43657370960 and 43657370973 at `a24f92c17f93d5c150eafe4ba7dce507ecb534b6`. The manifest validates run status, workflow identity and SHA; it does not independently establish every numeric claim from the job logs.
- Current remediation head must pass a new five-job integrated matrix, poster rendering, and additional security checks before merge. Six skips require explicit review.

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
