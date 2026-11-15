> **Verification update (2026-11-15 UTC; exact source SHA):** Gateway commit `8049ec46e8337ee4eabff9cfa97ffe4663f4febc` passed [nine-job Phase 1–16 integrated security CI](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43748347243) and [Poster Artifact Parity](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43748347212). The earlier PDF raster mismatch was traced to continuously animated SVG print frames; the print stylesheet now freezes animations, and the three committed poster binaries were regenerated ([reconciliation run](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43748301101)). Historical 782/81.93%, 1,245/6 and 1,246/6 figures belong only to their cited dated CI runs; the final nine-job run is **not** a newly measured coverage figure. This note records successful verification of the cited SHA, not automatic certification of later edits. **PRODUCTION NO-GO** remains in force.

# Individual-file adversarial audit register — 2026-11-15

**Baseline SHA:** `428ca84e6d693041f33985aef8c5a64aa558eae0`. **Production: NO-GO.**

GitHub tree inventory: **333 tracked blobs**, including 179 Python files and 73 Markdown files. This register covers **selected individually inspected files and line ranges**, not every line of every blob. No claim of full audit coverage is made.

| File | Lines examined | Finding / evidence | Status |
|---|---|---|---|
| `src/mcp_monitor/proxy/stdio_proxy.py` | 135–170, 495–576, 1220–1238 | Direct subprocess transport exists. Production mode explicitly requires strict offline Docker isolation (524–533), and sandbox modes prevent transport overrides (538–557). Outside production the default remains unsandboxed (561–563). | **PARTIAL:** investigate all callers and enforce operator threat boundary; not an established production bypass |
| `src/mcp_monitor/proxy/sandbox.py` | 23–73 | Offline Docker command includes network-none and cap-drop; pinned digest validation. | **PARTIAL:** runtime Docker/host isolation unverified |
| `src/mcp_monitor/proxy/internal_sandbox.py` | 14–77 | Internal sandbox replaces network-none with a configured internal Docker network. | **PARTIAL:** network membership and destination isolation need actual probe |
| `src/mcp_monitor/proxy/protected_repo_sandbox.py` | 1–91 | First-party protected server has separate operator-provisioned sandbox. | **PARTIAL:** independent bypass probe required |
| `src/mcp_monitor/protocol/revocation_fence.py` | 55–92, 115–140 | Private single-link SQLite file, BEGIN IMMEDIATE lock; local cooperative authority. | **PARTIAL:** no issuer-side revocation proof |
| `src/mcp_monitor/protocol/effect_journal.py` | 65–102, 110–140 | SQLite effect reservation rejects duplicates and marks uncertain state. | **PARTIAL:** independent external outcome unknown after lost acknowledgment |
| `src/mcp_monitor/proxy/oidc_identity.py` | 165–215 | Explicit RS256 verification, issuer/audience, tenant and session checks. | **POSITIVE scoped review:** issuer/JWKS rotation not end-to-end verified |
| `src/mcp_monitor/production/server.py` | 415–455, 510–535 | HTTP inspection uses configured API keys; telemetry best-effort. | **PARTIAL:** tenant and audit guarantees not established |
| `src/mcp_monitor/production/config.py` | 50, 86–87 | Production config rejects anonymous mode. | **POSITIVE scoped review** |
| `.github/workflows/release.yml` | 21, 60–88, 154–155, 194–202, 238–273 | Release environment and per-run generated validation credential; managed token references. | **PARTIAL:** environment protection and external issuer audit not inspected |
| `.github/workflows/security-hygiene.yml` | credential-pattern sections | Source/history regex checks exist. | **PARTIAL:** cannot prove no secrets in all refs/artifacts |
| `.github/workflows/poster-artifact-parity.yml` | 105–151 | Exact-head render, page dimensions and strict committed binary comparison. | **CONFIRMED FAIL:** CI run 43675623224 |
| `.github/workflows/phase1-16-integrated-security.yml` | 28–96 | Three-version regression and fail-closed coverage artifact upload. | **CI PASS:** run 43675623324 on baseline SHA; not production acceptance |
| `.github/workflows/production-gate.yml` | 1–39 | Production gate workflow present. | **PARTIAL:** no real deployment approval established |
| `.github/workflows/production-policy.yml` | 1–44 | Policy workflow present. | **PARTIAL:** not equivalent to environment protection |
| `deploy/k8s/deployment.yaml` | entire manifest | Invalid digest deliberately blocks unauthorized deployment; restricted security context. | **EXPECTED BLOCKER:** only replace with verified image digest |
| `deploy/k8s/networkpolicy-deny-all.yaml` | 1–19 | Denies selected gateway pod ingress and egress. | **PARTIAL:** CNI enforcement untested |
| `deploy/k8s/service.yaml` | entire manifest | ClusterIP plaintext HTTP with mTLS/ingress caveat. | **PARTIAL:** denied by default policy until exceptions |
| `deploy/k8s/configmap.yaml` | 1–24 | Configuration manifest inspected. | **PARTIAL:** runtime validation outstanding |
| `poster/render_poster.py` | 260–300 | Browser discovery and headless rendering without an explicit renderer version pin in the script. | **REPRODUCIBILITY RISK:** investigate metadata and raster parity |
| `poster/evidence_manifest.json` | evidence workflow references | Historical evidence pinned to earlier SHA. | **HISTORICAL:** not current-head approval |
| `SECURITY.md` | 1–41 | Separates source retirement from issuer revocation. | **POSITIVE scoped review** |
| `README.md` | 1–112 | Multiple dated CI snapshots, NO-GO status. | **PARTIAL:** remaining links/claims require individual verification |
| `PRODUCTION.md` | 1–48 | Explicit NO-GO and release conditions. | **POSITIVE scoped review** |
| `poster/01_research_brief.md` | status/metrics | Historical claims identified as snapshots. | **PARTIAL:** rendered artifact parity failed |
| `poster/02_claim_ledger.md` | status/claim table | Evidence claims categorized. | **PARTIAL:** verify current binary |
| `poster/03_verified_metrics.md` | status/metrics | 1,245 historical count distinguished from newer 1,246. | **PARTIAL:** verify current binary |

## Unresolved adversarial checks

1. Trace every production/non-production subprocess caller and confirm the intended isolation threat model, including direct downstream access.
2. Obtain actual poster artifacts and compare PDF metadata and rasterized pages; do not weaken parity without human approval.
3. Verify Kubernetes deny-all behavior with live ingress/egress negative tests.
4. Inspect all remaining source, test, workflow and Markdown files individually and record line-level evidence; do not label uninspected files reviewed.
5. Verify issuer-side credential revocation and scan all reachable Git refs and artifacts.
6. Independently test effect crash/retry and authority revocation against external ground truth.

**CI evidence:** [integrated success](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43675623324), [poster failure](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43675623224), both at baseline SHA.

**Audit is IN PROGRESS; production is NO-GO.**
