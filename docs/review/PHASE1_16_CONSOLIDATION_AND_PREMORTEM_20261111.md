# Phase 1–16 offline candidate — merge, threat and release gate

**Evidence review:** 2026-11-11, Arizona time. **Production: NO-GO.** This is an integration record, not a penetration-test certificate or release authorization.

## Three long-lived branch roles

| Branch | Exact purpose | Inbound merge rule |
|---|---|---|
| `main` | Stable public baseline; merged PR #180 introduces live stdio tool policy enforcement and refuses uncontained production mode | Only scoped peer-reviewed fixes with exact-head green CI; never use as an automatic production promotion trigger |
| `release/phase1-16-offline-rc-20261111` | Integration and hardening candidate for exactly one restricted first-party manifest MCP workflow in offline Docker | Preserve reviewed controls, run all relevant workflows, require independent review; no provider effects or internet egress |
| `research/phase1-16-adversarial-20261111` | Detector experiments, public-corpus benchmarks and exploratory protocol/security research | No direct promotion into release; require separate frozen evaluation, security review and task-oriented tests |

Other feature branches and stacked PRs are **historical review records**, not an instruction to merge them all. A GitHub green CI check is not a release-signature.

## Actual code lineage

- Public `main` merged PR #180 as commit `6ff6a5abd40d59bd263548b6ec42581a2ee05fbd` on 2026-11-11 Arizona time.
- The offline RC is descended from the stacked Phase 1–16 source as of PR #182, with the security-only outcome-verification changes from PRs #181 and #184 selectively incorporated. The separate new external benchmark from PR #183 is **not incorporated**.
- Reconciliation preserves the RC's stronger, strict, offline-only stdio implementation and the newly merged main history, while retaining the main live-policy backport regression tests for cross-checking. This is a **source reconciliation requiring exact-head CI**, not proof that all past PRs have been individually code-reviewed.
- The release branch is not production GO, even when all CI jobs are green.

## Devil's advocate: counterclaims to our strongest assumptions

**Claim: all MCP actions must pass our proxy.** Counterexample: an agent with direct file, Docker daemon, browser or network capabilities could bypass the stdio channel. The offline container is bounded; the whole host is not. Demonstrate a dedicated nonprivileged client OS identity unable to access protected resources or Docker sockets, network routes or downstream credentials outside the gateway.

**Claim: pattern detection secures document and Hugging Face content.** Counterexample: the external 303-case public corpus gave regex TP28/FN172/FP0/TN103 and locally trained hybrid TP64/FN136/FP0/TN103, versus much stronger synthetic author-curated recall. The benchmark is diagnostic, not a real MCP attack-success experiment. No general content is proven byte-for-byte safe to interpret as instructions. Only explicit tool authorization and content-as-data separation can serve as primary controls.

**Claim: `result` means a tool action succeeded.** Counterexample: the downstream server can acknowledge before execution or falsely claim success. The generic journal now holds `UNCERTAIN` and returns an explicit unverified-outcome error. Completing the journal requires a trusted, independently observed effect and reconciler; this is not yet integrated for external providers.

**Claim: pinned Docker and green scanning prove secure supply chain.** Counterexample: a digest pins bytes, not trust; OS packages, dependency transitive behavior, image signature, vulnerabilities without advisories and reviewer provenance require independent scrutiny.

**Claim: production API keys are banned, so remove authentication.** This is unsafe. The restricted local offline profile does not use third-party provider keys. The separate networked HTTP inspection service requires operator-controlled authentication and is outside the release-candidate scope. Do not make it anonymous to satisfy a keyless requirement.

## Autopsy — cause, mechanism, evidence, repair

| Severity | Cause / failure mode | Verified evidence or gap | Corrective next step |
|---|---|---|---|
| Critical | Host bypass, independently started MCP server or Docker socket | Offline Docker negative tests; host non-bypassability **not proven** | Deploy a separate least-privilege identity, remove direct downstream credentials/capabilities, test hostile host/process paths |
| High | Trusted caller/tenant identity incomplete | Local session signatures, optional offline OIDC/JWKS, local ACL fence | Select real deployment and identity provider; exercise revocation/tenant races at each supported entry point |
| High | Spoofed success and uncertain effects | Exact-operation permits, SQLite journal and manifest-specific checks; generic remote effects **not verified** | Explicit independently observed consequence adapter and manual reconciliation protocol, no automatic retry |
| High | Prompt-injection false negatives | Author-curated 96-case and external 303-case tests disagree strongly | Freeze independently curated indirect MCP/tool-response holdout, include legitimate quoted security data |
| High | DNS, redirects, IP/port validation for outbound internet | Offline profile blocks outbound network; networked pilot isn't a release-boundary proof | Keep network disabled for RC; defer online deployment until network egress socket-level tests |
| High | Power failure and multi-host state | Tested process kills and SQLite local durable reservations | Test actual forced host power loss/filesystem durability, backup/restore, cluster conflicts and cross-host races |
| High | Independent adversarial sign-off | No external reviewer approval or realistic deployment pen test | Assign reviewer and documented scope, remediate findings, sign reviewed risk register |
| Medium | Vulnerabilities and secrets | Configured scans and installed Python SBOM green, known source demo key retired | Include image OS packages/licensing/attestations, inspect deployment secret stores, revoke only confirmed active provider credentials |
| Medium | Documentation and marketing claims | Historic Markdown notices and a regenerated poster | Line-by-line independent claim register with exact version and source snapshots |

## Postmortem (evidence-based, no invented incident)

There is **no verified production incident** to attribute here. The observed failure was release process fragmentation: dozens of stacked drafts, older main lacking the hardened policy, and historical metric snapshots reused outside their exact source context. Underlying cause is an unfinished integration/release process, *not* proof of a successful attack.

## Premortem: likely reasons a production attempt would fail

1. An agent directly invokes an MCP server using a credential or file mount absent from the enforced proxy.
2. An attacker places an instruction inside fetched document/model metadata and the detector misses it; an unrelated authorization weakness allows harm.
3. A remote action reports success, the agent assumes completion, then retries following an ACK loss; the action occurs twice.
4. Revocation arrives between authorization and the protected file commit.
5. A mutable transitive package, container base or compromised deploy secret subverts an otherwise green candidate.

## Independent release requirements

- Freeze a **single** release candidate and **exact source SHA**; collect green CI, static/dynamic/negative test evidence and independent review on **that SHA**.
- Make authorized client identity and deployment bypass boundaries explicit and test denied direct access to protected files, socket/ports, browser profiles and Docker API.
- Keep side effects offline and limited to allowed `package.json` edits. Do not enable web booking, payments, remote Hugging Face downloads, general file reads, or privileged shell.
- Have an independent reviewer sign residual risks, dependency license and credential inventory, operational recovery/rollback plan, and supported MCP protocol matrix.
- Operational verification and human approval are mandatory and cannot be substituted by CI or assistant statements.

**Decision: PRODUCTION NO-GO; OFFLINE EXPERIMENTAL RELEASE CANDIDATE ONLY.**
