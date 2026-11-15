# Phase 1–16 MCP Gateway: forensic post-mortem, devil's advocate and release gates

**Assessment date:** 2026-11-14 America/Phoenix / 2026-11-15 UTC  
**Scope:** Public repository `poojakira/mcp-agent-security-gateway`, audit branch `security/phase1-16-audit`.  
**Verdict:** **DEVELOPMENT REGRESSION GREEN AT SPECIFIC TESTED SHA; PRODUCTION NO-GO.**

## Executive determination

The 2026-11-14 full-regression failure chain was a *formatting gate*, not a Python test failure. Earlier audit-head workflow [43655178466](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43655178466) failed because Ruff would reformat a call in `src/mcp_monitor/protected_repo_server.py`. All three Python jobs exited before full `pytest`; Docker sidecar and lab-security jobs succeeded. Commit `5978d483329c4c3c29e313846172aeb75b2b2fc3` corrected the formatting without suppressing tests. [Run 43656575066](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43656575066) then passed all five jobs. The full suite reported **1,236 passed / 6 skipped per Python 3.10, 3.11 and 3.12**. No contemporaneous overall coverage result was verified. [Poster parity 43656574988](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43656574988) passed on the same source SHA.

These are **exact-commit** results. They cannot certify later release-authorization or documentation changes without another successful run.

## Workflow inventory and provenance

A complete Git tree inventory at the tested SHA showed **25 files in `.github/workflows/`**. I inspected their event/triggers and reviewed a GitHub Actions history sample spanning approximately July–November 2026 (about 3,189 run records returned across pages). Old successful phase workflows are **not exact-head validations** of the current audit branch. Most standalone phase workflows do **not** automatically trigger on `security/phase1-16-audit`; many support manual `workflow_dispatch`. CI, Security Hygiene, Production Gate, real filesystem smoke and independent specialty tests have successful *historical* runs on other branches. A job named "Production Gate" passing is insufficient for production acceptance.

The currently validated audit-head workflow pair is:
- [Integrated security 43656575066](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43656575066) — 5/5 jobs, 1,236 passed + 6 skipped on each of three Python versions, pinned source SHA `5978d483...`.
- [Poster artifact parity 43656574988](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43656574988) — generated 36×48 PDF and PNG artifacts with automated dimension/content checks at the same SHA. The committed poster binaries may be from earlier inputs; do not distribute them as current without comparing the artifacts and inspecting the rendered output.

## Branch deletion and provenance recovery

The public `integration/phase1-16-verified` branch was deleted manually and recreated from `security/phase1-16-audit`. GitHub compared the two recreated refs as identical at that moment. **The exact deleted integration-head commit was not independently recovered.** Later audit work advanced the security branch while keeping `main` unchanged. The private repository's similarly named branch was intact at the time checked. Review unique commits and PR head/base references before further branch deletion or merge.

## Post-mortem: five causes and safeguards

| Cause / contributor | Evidence | Corrective control |
|---|---|---|
| Formatting gate masked downstream tests | Ruff required a single-line call in `protected_repo_server.py`; three Python jobs stopped before pytest | Corrected source formatting; integrated suite subsequently passed |
| Historical metrics appeared beside live branches without exact-SHA qualification | Poster/Markdown cited 1,211-pass results from `43a72c8984bf9a472b9055d4f9e84cc759f61718` | Cite the newer 1,236-pass run with exact SHA and preserve older results as historical |
| Source branches were deleted before all PR/provenance review | Integration ref required recreation; original head unknown | Preserve branch refs; export SHA inventory and PR associations before deleting more branches |
| The release workflow had publishing steps reachable after a tag and ordinary checks, without an explicit SHA-locked release-decision gate in its YAML | `.github/workflows/release.yml` tag trigger and publish steps | Added `scripts/check_release_authorization.py`, requiring explicit GO, approved tag/SHA and approval reference; provision **release environment required reviewers** separately |
| Many workflows were not configured to run on this audit branch | 25 workflow configurations; independent phase workflows often run on their historical heads only | Compare each workflow's exact commit, triggers, artifact provenance and residual risk; manually dispatch required checks at the audit head |

## Devil's advocate: what tests do *not* establish

1. **Bypass/non-bypassability.** A same-user process able to invoke the protected MCP server directly may evade an upstream gateway; local process restrictions and Docker isolation do not establish host-wide interception. Treat this as **critical** until the intended deployment denies direct socket/process/volume/Docker-daemon access and a red team demonstrates it cannot bypass policy.
2. **Identity.** A trusted local operator principal and SQLite revocation do not prove federated caller identity, consent, remote-user proof, role changes, tenant isolation or access revocation across every transport. Test forged actors, duplicate sessions, key rotation, stale tokens and authority service outages.
3. **Revocation race.** `BEGIN IMMEDIATE` serializes cooperative local writers; it does not revoke a process that uses another authority file or bypasses the fence. Test revocation at each boundary (before reservation, during tool execution, after effect, on reconnect, concurrent child processes).
4. **Network controls.** A Docker `--network=none` profile is a bounded offline guarantee, not a general-purpose egress firewall. In any network-enabled deployment, separately test redirects, DNS rebinding, IPv4/IPv6, proxy variables, internal ranges and direct host networking.
5. **Side effects.** A successful MCP response is not an independently observed external outcome. The repository has local manifest checks and uncertain-effect journaling; it has no demonstrated reconciliation for remote bookings, payments, tickets or healthcare systems.
6. **Crash safety.** Child-process SIGKILL tests do not prove power loss, inode durability across hostile filesystems, distributed split-brain, or exactly-once remote effects.
7. **Detection efficacy.** The 96-case author-curated regex set (TP40, FN8, FP16, TN32) is not independent blinded field validation. There is no statistically defensible promise of a detection rate in arbitrary production data.
8. **Secrets and supply chain.** A clean scanner and public-dependency audit are scoped observations. They do not search every issuer secret store, private history, local developer machine, registry image or deployment. Removing an exposed demo key from code is *not* issuer-side revocation.
9. **Release provenance.** A valid GitHub Actions run and signed artifact do not imply release authorization. An admin able to edit environment variables, workflow files or branch policy may bypass a weak approval process; required reviewers, protected tag rules, permissions and independent attestation must be configured and tested.
10. **Poster claims.** An animated diagram shows intended architecture, not runtime efficacy. Static PDF and PNG must be regenerated from the matching claim ledger and visually inspected.

## Release authorization remediation

An audit-branch change introduced the `scripts/check_release_authorization.py` gate and `tests/test_release_authorization.py`; the Signed Release workflow now requires:
- `GITHUB_REF_TYPE=tag` and a valid tag and full Git commit SHA.
- `MCP_RELEASE_GO=true`.
- `MCP_RELEASE_APPROVED_TAG` matches the running tag.
- `MCP_RELEASE_APPROVED_SHA` matches the exact `GITHUB_SHA`.
- Nonblank `MCP_RELEASE_APPROVAL_REFERENCE`.

**This is a fail-closed administrative safeguard, not a security proof or permission to release.** Configure environment-protected variables and required human reviewers on the `release` GitHub environment; restrict tag creation/push, protect branches, and require approval records outside the repo. The tag workflow is not itself exercised by the branch regression run, and all automatic publish operations must remain disabled until accountable release approval.

## Evidence acceptance and next verification

1. Run integrated full `tests/` matrix and newly added release-gate tests on the **actual latest source SHA**. Require all jobs green and explicitly account for skips; do not silently increase pass counts.
2. Review and run lint, Bandit, dependency scanning, SBOM/license inventory, CodeQL, production-gate and real MCP/Docker workflows at their exact relevant heads. Historical pass is not current proof.
3. Perform fresh external bypass attempts: direct server, altered MCP tool paths, malformed/duplicate JSON-RPC, revocation races, process-kill and effect replay; independently inspect state.
4. Generate poster PDF/PNG at the exact current docs SHA and check readable labels, numerical provenance and print dimensions. Keep source SVG illustration and finished artifacts distinct.
5. Preserve the release decision as **NO-GO** pending independent red-team/IV&V, trusted remote identity, non-bypassable deployment, egress control, verified remote outcomes, issuer-side secret review, and accountable GO signature.

## Non-claims

This audit does not certify a full production service, universal prevention, independent penetration testing, complete secret revocation, zero vulnerabilities, exact historical integration recovery, or a published production-safe poster. All conclusions are bounded to observed GitHub source, displayed CI logs and documented tests.
