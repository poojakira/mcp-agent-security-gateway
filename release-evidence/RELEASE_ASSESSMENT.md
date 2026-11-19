# Release assessment: mcp-agent-security-gateway

SOURCE: `d2e7b6ea7c1a1f9cb0fb71f73d0a692d8fa0410c`  
BRANCH: `codex/local-workbench-20261116`  
ASSEMBLED UTC: 2026-11-19T00:50:24.946932+00:00  
DECISION: **PARTIAL**. No software release, main merge or public full-app deployment is approved by this assessment.

Agent developers submit a bounded MCP request, change permissions and inspect actual fixed-child receipts and disposable tool-side state. Policy decisions and execution outcomes remain distinct.

## Working entry points

- [Current source README and exact local prerequisites/launch](https://github.com/poojakira/mcp-agent-security-gateway/blob/d2e7b6ea7c1a1f9cb0fb71f73d0a692d8fa0410c/README.md)
- [Free CPU guided notebook](https://colab.research.google.com/github/poojakira/mcp-agent-security-gateway/blob/codex/local-workbench-20261116/notebooks/try_product.ipynb) — public page HTTP 200; actual committed cells passed locally from a fresh public checkout, **hosted Colab kernel NOT VERIFIED**.
- [Readable overview](https://github.com/poojakira/mcp-agent-security-gateway/blob/d2e7b6ea7c1a1f9cb0fb71f73d0a692d8fa0410c/docs/architecture/overview.svg), [detailed source-mapped architecture](https://github.com/poojakira/mcp-agent-security-gateway/blob/d2e7b6ea7c1a1f9cb0fb71f73d0a692d8fa0410c/docs/ARCHITECTURE.md), and locally served zoom/pan viewer in `docs/index.html`.

Actual guarded read; same write denied with no receipt; same write allowed after permission change.

The full browser UI remains a local application with its own documented supported inputs. Notebook fixtures do not establish representative field detection, a public hosted full UI, continuous monitoring or multi-user isolation. GitHub Pages configuration failed with HTTP403 "Resource not accessible by integration"; no working Pages URL is asserted. No Render/HF compute resource, paid service, billable provider API call or new credential was used. Existing optional cloud/deployment templates can cost money if separately enabled; see `cost-and-access-audit.json`.

## Fresh execution evidence

The clean candidate has **834 passed, 0 skipped, 0 failed and 0 errors** across 834 individual testcases. Local statement/line coverage is **81.80446084%** (4878/5963); recorded gate 77. Native subtests: {'passed': 0, 'failed': 0, 'skipped': 0}. Separate Python3.10 focused execution: None. Focused/optional/native/browser observations are not added to the individual full-suite total.

See `manifest.json`, `primary-run-manifest.json` where present, `tests-run.json` for Aegis, `executed-test-inventory.json`, original logs, and `browser/` for exact commands, execution times, clean source, environments, skip reasons and actual screenshots/exports. Required named local gates passed. No check threshold was reduced. Installed-wheel execution uses an unrelated Git project and verifies UNKNOWN instead of inheriting its HEAD.

Current hosted runs: 7 observed; all successful: True. `remote-ci/status.json` records actual URLs and statuses. The downloaded acceptance ZIP digest and every embedded artifact hash were independently recomputed locally; the manifest identifies this exact clean source. Hosted coverage is kept in remote-ci/hosted-manifest.json and is not substituted for local coverage. No publishing workflow or release was invoked.

The earlier 05aa Docker run failed because demo fixtures were missing from the builder and a new provenance test assumed Git existed. Candidate d2e fixes builder-only fixture copying and explicitly tests UNKNOWN when Git metadata is absent; it retains the complete regression and coverage gate. Current hosted CI including Docker Build succeeds. No product assertion, security threshold or test was skipped to make that pass.

## File, documentation, branch and security audit

252 tracked files were inventoried with SHA256 and per-type validation; all current local documentation target checks, 3 SVG XML parses, notebook JSON/compiled cells and viewer JavaScript syntax passed. Actual viewer controls and every diagram loaded in desktop/mobile Chromium with no page errors. Four sequential product documentation reviewers inspected architecture symbols/enforcement/limits; the parent corrected remaining source mismatches and readability. Historical documents/artifacts retain their dated source bounds. This audit does not certify every external link's factual content, chronology, optional toolchain or cloud/deployment command.

Only `main` and `codex/local-workbench-20261116` remain as remote branches at recorded readback. Main remains `6ff6a5abd40d59bd263548b6ec42581a2ee05fbd`. 6 additional tips were preserved in verified annotated recovery tags and a private verified bundle before exact-lease atomic deletion. 4 associated PRs are closed without merging their unreviewed changes. Unique security/cross-language work remains recoverable, not advertised as current functionality. Restore commands, tag/SHA pairs and final PR states are in `branch-disposition.json`. Tags are not extra branches. Future dependency automation may create branches; its protections were not disabled.

The reviewed offline Gitleaks scan covered all local Git refs/history, including recovery history, with redaction and default detectors. It produced 1334 historical generic-rule occurrences, explicitly classified in `secret-history-triage.json`; no confirmed provider credential was found in that reviewed scope. Current tracked-file scanning found no new heuristic secret values. Hashes, public signing fingerprints and intentional synthetic/local test examples are distinguished from provider credentials. No live credential validation, suppression baseline or absolute secret-absence claim is made. Private raw history/author context, backups, product credentials, session tokens and real patient/user data are excluded from publication.

## Independent review boundary and remaining release gates

Historical focused independent security reviews remain attached to their real earlier source. Current whole-suite/browser/build/type/security checks were freshly executed by the parent. Documentation role separation is not a newly completed independent adversarial closing review at this candidate. HF's explicit blocked review remains blocked, with no bypass or reroute. No perfect/production-ready claim is justified.

- Current complete MCP conformance, cancellation/concurrency and credential lifecycle are NOT VERIFIED or NOT IMPLEMENTED.
- Arbitrary-server OS containment, external side-effect reconciliation, response PII filtering and externally anchored audit custody are NOT IMPLEMENTED or NOT VERIFIED.
- Native Make checks are separate; CMake and Rust toolchains are absent.
- Deployment-specific privacy, recovery, load and hostile public-hosting approval are NOT VERIFIED.

`product-matrix.json` maps current implementation/evidence and gaps. `executed-test-inventory.json` identifies actual positive/negative/recovery cases and skipped checks. A new current-source independent review, the missing product-specific acceptance gates and deployment-specific signoff would be required to change this decision.

NEXT SAFE ACTION: review the existing draft PR and the source-scoped archive; complete the listed acceptance gates. Any later source change requires fresh applicable regression/browser/security evidence.
