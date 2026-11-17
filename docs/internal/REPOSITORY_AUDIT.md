# Read-only forensic baseline: poojakira/mcp-agent-security-gateway

UTC: 2026-11-17T02:26:33.787101+00:00. Audit role: independent forensic reviewer. Decision: PARTIAL baseline; product release NOT VERIFIED.

## Repository identity

Authoritative connected-account match: `poojakira/mcp-agent-security-gateway`; public; remote `https://github.com/poojakira/mcp-agent-security-gateway.git`; default `main`; HEAD `6ff6a5abd40d59bd263548b6ec42581a2ee05fbd`. Full fetched reachable history contains 983 commits; no shallow clone, no source/remote mutation performed. No AGENTS.md found. Commit metadata and all reachable commit parents/dates/subjects: `git-baseline.json`, `history.txt`.

Initial checkout status: ' M README.md\n M RESEARCH_REPORT.md\n M RESUME_EVIDENCE.md\n M VERIFIED_METRICS.md\n M docs/APPSEC_CASE_STUDY.md\n M docs/RECRUITER_EVIDENCE_AUDIT_2026-10-09.md\n'. MCP six trailing mixed-CRLF lines normalize on checkout under .gitattributes; preserved in normalization.patch. Do not attribute these to user edits. No reset or overwrite performed.

## Product baseline

Capabilities: Real Python PolicyEngine, live StdioMCPProxy, hash-chain audit, injection/PII/egress checks; browser dashboard streams inspection decisions.

Gaps: No browser request/policy editor, disposable tool workspace or confirmed tool-side outcomes in main UI. Production CLI fails closed without isolation. Main and 528-commit feature branch have materially different security paths.

Risk: HIGH: do not infer downstream execution from inspection ALLOW. Enhanced candidate exact-image acceptance failed at 40c5f2b5; unreviewed feature merge would import 225 changed files / 25k lines. README current metrics refer to older October source.

Minimal complete journey: Browser request -> existing live stdio proxy -> first-party disposable protected server -> inspect policy/actual file state -> change policy and rerun -> evidence export.

Enforcement/source entrypoints: src/mcp_monitor/policy/policy_engine.py: PolicyInput.from_tool_call, PolicyEngine.evaluate; src/mcp_monitor/proxy/stdio_proxy.py: inspect_message, StdioMCPProxy.handle_message; src/mcp_monitor/audit/log.py; src/mcp_monitor/server/realtime.py: api_scan. api_scan evaluates FiveLayerDefense; dashboard does not prove action execution.

Recommended next milestone: Start on reviewed main for small bounded UI adapter, or explicitly review protected server/journal diff before basing candidate on origin/fix/evidence-provenance-20261114. Preserve all three substantial enhancement branches. Do not claim production isolation or image release while exact-image check fails.

## Current CI and executable evidence

Main CI success run 43833598479 at 6ff6a5ab. Enhanced branch integrated run 43987966883 SUCCESS; P0 exact-image run 43987966844 FAILURE at 40c5f2b5. These are retrieved historical runs, not newly executed release evidence.

Fresh local command (from repository root):

```sh
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=src /workspace/work/tooling/venv/bin/python -m pytest -p no:cacheprovider tests/test_policy_enforcement.py tests/test_live_stdio_policy_backport.py tests/test_protocol_hardening.py -q --junitxml=/workspace/work/audit/mcp-agent-security-gateway/baseline-junit.xml
```

Result: 59 passed, 0 failed, 0 skipped; focused suite only; no coverage measured. Actual captured output: baseline-tests.log; JUnit: baseline-junit.xml. Tests were run from original main source in audit tooling venv; this is not a candidate release run. Python 3.12.14; Node 24.22.1; Linux. Generic tooling venv is not the complete pinned product dependency environment. Exact run timestamps/counts are in JUnit. Final candidate tests, full regression, browser E2E, supply-chain audit, container build and release validation are NOT VERIFIED. Do not treat retrieved historic CI as fresh evidence.

## File inventory and validation

Every tracked default-branch path inventoried: **217**. `inventory.json` records path, size, SHA256, type, symlink state, AST/JSON syntax validation; `tracked-files.txt` is complete path list. Python AST syntax and tracked JSON parsing completed with 0 errors. `configuration-validation.json` records safe TOML and shell syntax checks. `documentation-inventory.json` inventories 43 text documentation files and candidate broken local links; external URLs, anchors, all facts/examples and media visual accessibility remain NOT VERIFIED. `workflow-audit.json` records source workflow pin/permissions indicators; parser/trigger and gate semantics need final review. No arbitrary tracked binary/executable or model was executed. Binary fixture hashes are inventory evidence, not proof of safety. No submodules. Test classes inferred from source include unit, integration, negative/adversarial; exact taxonomy and coverage exclusions must be reviewed for candidate.

All tracked-file semantic/security review is NOT COMPLETE. All remote branch tips have diff-stat and changed-path evidence; only selected important source paths were reviewed semantically. This records the audit boundary rather than falsely claiming every historical branch file/claim was verified.

## Branch governance

All refs preserved. Ahead/behind are ancestry counts, not evidence that squash-merged content is missing. No branches merged/deleted; none is yet DELETE ELIGIBLE. Full unique commit lists are in git-baseline.json. PR metadata latest first-page stored in github-prs.json (max 100; older pagination not yet exhausted). Open PRs visible in first page retained. Tags: none. Releases: none returned. Rulesets: empty returned. Branch-protection inspection BLOCKED by GitHub integration 403; lack of visibility does not establish absent protection. Workflow collection endpoint was rejected; checked-in workflow sources and action-run endpoints were read.

| Ref | SHA | Ahead / behind main | Disposition | Related PR |
|---|---|---:|---|---|
| `refs/heads/main` | `6ff6a5abd40d59bd263548b6ec42581a2ee05fbd` | 0 / 0 | KEEP |  |
| `refs/remotes/origin/HEAD` | `6ff6a5abd40d59bd263548b6ec42581a2ee05fbd` | 0 / 0 | KEEP |  |
| `refs/remotes/origin/dependabot/github_actions/docker/login-action-4.8.0` | `c996af5b3eaa1203bca805f008a45a5efb258cb0` | 1 / 0 | HOLD FOR REVIEW | #192 open |
| `refs/remotes/origin/dependabot/github_actions/github/codeql-action/analyze-4.39.3` | `15d84bfcda15bb8df703acc71708d5b1c9f44b34` | 1 / 0 | HOLD FOR REVIEW | #193 open |
| `refs/remotes/origin/dependabot/github_actions/softprops/action-gh-release-3.0.4` | `5f650f6c58ec254b2a696564dfd67ecd75fcd08e` | 1 / 0 | HOLD FOR REVIEW | #191 open |
| `refs/remotes/origin/dependabot/pip/ruff-0.17.5` | `32db44597b86a48d12b6a53f962e6cfcf5ec0b91` | 1 / 0 | HOLD FOR REVIEW | #190 open |
| `refs/remotes/origin/docs/cerberus-integration-closure-2026-10-09` | `f34e392fa5029ba32c2ef900877273276c81e7ea` | 2 / 18 | HOLD FOR REVIEW | #115 closed |
| `refs/remotes/origin/fix/evidence-provenance-20261114` | `40c5f2b5b887d1c7f02d7054b0af3a95a10d0323` | 528 / 0 | HOLD FOR REVIEW | #188 closed |
| `refs/remotes/origin/integration/phase1-16-verified` | `4d37d68330b79cde36376272f47d007d234681fd` | 384 / 0 | HOLD FOR REVIEW |  |
| `refs/remotes/origin/main` | `6ff6a5abd40d59bd263548b6ec42581a2ee05fbd` | 0 / 0 | KEEP |  |
| `refs/remotes/origin/security/phase1-16-audit` | `2158ab58e4a07a5c49b70c659996653a92f661c8` | 407 / 0 | HOLD FOR REVIEW | #187 closed |

## Phase report

PRODUCT: poojakira/mcp-agent-security-gateway
SOURCE: 6ff6a5abd40d59bd263548b6ec42581a2ee05fbd BRANCH: main UTC: 2026-11-17T02:26:33.787101+00:00
PHASE: 0 forensic baseline
DONE: complete default tracked-path/hash inventory; reachable refs/history; selected engine/UI/docs/workflow analysis; raw provider evidence.
EXECUTED: command above; safe Python AST/JSON/TOML/bash syntax checks; git read-only inventory; GitHub GET metadata.
RESULTS: 59 passed, 0 failed, 0 skipped; focused suite only; no coverage measured.
NEGATIVE / ADVERSARIAL TESTS: focused existing tests named by command; no new full acceptance attack matrix executed.
CLAIMS VERIFIED: source existence and selected behavior only; see checks above.
CLAIMS RETRACTED: no source changes during audit; unsupported/stale claims flagged above for implementation/docs reviewer.
BRANCH CHANGES: none; all KEEP or HOLD FOR REVIEW.
RISKS / BLOCKERS: incomplete release acceptance and provider protection visibility; product-specific items above.
DECISION: PARTIAL baseline; NOT VERIFIED release.
NEXT SAFE ACTION: Start on reviewed main for small bounded UI adapter, or explicitly review protected server/journal diff before basing candidate on origin/fix/evidence-provenance-20261114. Preserve all three substantial enhancement branches. Do not claim production isolation or image release while exact-image check fails.
