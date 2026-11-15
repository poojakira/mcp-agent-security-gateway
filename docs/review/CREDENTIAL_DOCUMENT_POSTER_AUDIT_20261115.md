# Credential, documentation and poster adversarial audit — 2026-11-15 UTC

**Decision: PRODUCTION NO-GO.** Scope: GitHub-connected branch `fix/evidence-provenance-20261114`; no access to issuer consoles, live secrets, all repository history, private CI environment values or production deployment. No credential was revoked; never equate source deletion with issuer revocation.

## Inventory and inspected scope

- Git tree inventory: 332 tracked blobs, including approximately 70 Markdown files, generated poster PDF/PNG and the animated SVG. **Inventory is not a claim of line-by-line inspection.**
- Individually inspected: README, PRODUCTION, SECURITY, VERIFIED_METRICS, RESEARCH_REPORT, poster source/metrics/claim ledger/reproducibility, Phase 13 credential audit, Phase 1–16 remediation tracker, repository postmortem, detection-lab Compose, main Compose, Kubernetes Secret template, release and security-hygiene workflows, poster renderer and evidence manifest.
- Not comprehensively examined: every source/test line, all 70 Markdown files, complete Git history, other branches, CI secrets, runtime environment, GitHub secret-scanning alerts, issuer logs and external deployment. **No repository-wide absence-of-secrets claim is authorized.**

## Credential findings

1. **Known historical exposure:** public detection-lab configuration previously included a fixed reusable demonstration gateway credential. Current branch requires `MCP_API_KEY` from the operator. The source-retirement and local fingerprint rejection documented in `PHASE13_SECRET_AND_CONTROL_AUDIT.md` do **not** prove issuer-side revocation, historical invalidation, or replacement in running instances.
2. **Release workflow:** a static `release-validation-key-at-least-32-characters` was previously embedded as a release test credential. Replaced with a randomly generated 32-byte hex value written to `GITHUB_ENV` per run. This is a local validation credential, not evidence of an active vendor-issued API token. Review the new workflow on its exact commit before claiming the gate passed.
3. **Current Compose and Kubernetes examples:** `docker-compose.detection-lab.yml` requires a supplied key; `docker-compose.yml` references optional environment credentials; `secret.example.yaml` is a non-applyable `SecretTemplate`. None of these proves actual issuer-side secret inventory or revocation.
4. **GitHub Actions:** `secrets.GITHUB_TOKEN` and optional `secrets.PYPI_TOKEN` are references to managed secrets, not embedded token values. Token values were not accessed or disclosed.
5. **Next credential actions:** authorized operator must check GitHub secret-scanning alerts and reachable/all refs, inspect Actions secrets and external stores, identify any active historical credential, revoke it **at its issuer**, rotate deployed credentials, invalidate sessions, inspect usage logs and preserve redacted evidence. Without issuer access, status remains **UNVERIFIED**.

## Documentation and poster accuracy findings

- Historical 782/1,211/1,245/1,246 counts coexist across docs; they are not inherently inconsistent if each is tied to its original SHA/run and date. Do not sum matrix passes or promote historical counts to the current head.
- Verified nine-job integration: [run 43674555508](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43674555508) succeeded at `39c8566e40d4ab89ceb7fda61999de205cb35604`. Later edits are not certified by it.
- The six generic matrix skips are still skips; dedicated Phase 5/9/14, official filesystem and pinned public manifest jobs passed on the cited nine-job run. This does not mean every scenario in every transport or real deployment was tested.
- Current poster workflow [43675028186](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43675028186) failed. Its PDF bytes do not match committed PDF. Chrome-rendered binary differences may reflect metadata or substantive layout; no visual-equivalence proof exists. The frozen `poster/evidence_manifest.json` pins historical evidence, not a current poster approval.
- README and poster source docs now carry a current-status banner but preserve older evidence with explicit historical scope. Other archived/phase documents retain dated snapshots and should be audited individually before external publication.
- `deploy/k8s/deployment.yaml` has an intentionally invalid digest placeholder. A new default-deny NetworkPolicy is source-level hardening only; no live CNI enforcement was demonstrated.
- Research novelty, complete credential hygiene, production readiness, independent security certification and all 42 remediation requirements are **not established**.

## Devil's-advocate acceptance questions

- Can an attacker reuse the old credential against a running deployment or alternate branch? **Unknown without issuer/runtime inspection.**
- Are all Git history refs, PR forks, artifacts, caches and logs free of credentials? **Not established.**
- Does the generated poster visually match the committed artifact and its numerical claims? **Not established; binary parity fails.**
- Does nine-job CI prove non-bypassable enforcement or remote revocation? **No.**
- Are historic Markdown claims clearly scoped to their original evidence? **Partially; priority docs annotated, full document-by-document audit outstanding.**
- Can a reviewer reproduce exact poster output in a pinned environment? **Not established.**

**Required closure:** explicit credential-issuer records, full repository/history and artifact scans, per-file documentation claim ledger, deterministic poster rendering and human visual review, current-head CI, and independent deployment/penetration evidence. No silent status upgrades.
