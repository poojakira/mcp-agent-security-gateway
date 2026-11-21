# Audit findings

## Repository state

Default branch main is 6ff6a5abd40d59bd263548b6ec42581a2ee05fbd. Review started at d2e7b6ea7c1a1f9cb0fb71f73d0a692d8fa0410c. The collected inventory contains 185 pull requests, 1 issues and 11 Git tags. The public Releases API returned zero release records.

### Open pull requests

- [#194 Add local MCP policy execution workbench and source-scoped verification](https://github.com/poojakira/mcp-agent-security-gateway/pull/194)

Draft #194 was open and mergeable at the observed base and head. Audit assessment is **NEEDS FIXES**.

### Open issues

No open issues in the collected inventory.



### Hosted runs in collected history

- Success on d2e7b6ea7c1a1f9cb0fb71f73d0a692d8fa0410c, 2026-11-19T00:39:00Z. [CI](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/44429942445)
- Failure on 05aa18fdbe95dbaaa8dfe610c704b39f12c7a00d, 2026-11-19T00:24:57Z. [CI](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/44428280605)
- Cancelled on 1801a1d8035a2cadda627fd7c5c312cf5e458982, 2026-11-14T21:47:35Z. [Development package gate (production NO-GO)](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43644579572)

Historical CI failure 44428280605 ran the Docker builder. Its pytest subprocess exited 2. This was a test/collection failure, category B, at that source. The cited later CI run succeeded.

## Confirmed defects

| ID | Severity | Affected file and lines | Root cause, impact and remediation | Status |
|---|---|---|---|---|
| MCP-01 | Medium | .github/workflows/ci.yml:45–50 | A pip install piped to tail could return success on failed installation. CI invokes pip directly. | Implemented locally |
| MCP-02 | Medium | .github/workflows/ci.yml:153–164 | The collection pipeline disregarded pytest’s status. The patched step checks the status before counting and retains the ten-test minimum. | Implemented locally |
| MCP-03 | Medium | src/mcp_monitor/siem/lifecycle.py:55–67 | The coverage matrix failed to load its Elastic TOML in a wheel-only install. The wheel packages the canonical data file and the lookup supports checkout, installed package and the explicit environment override. | Implemented locally |
| MCP-04 | Low | README.md and docs/BRANCHES.md | Both files referenced a missing branch-cleanup.json in the evidence archive. HTTP returned 404 and the named object was absent from Git. The links now point to the existing immutable manifest or cleanup record. | Implemented locally |

## Residual risk

Four open CodeQL comments about implicit string concatenation were addressed in demo/adapter.py. The bounded fixed-child workbench does not establish universal proxy mediation, concurrent revocation, exactly-once external execution, response PII filtering, live SIEM integration, audit anchoring, or transport conformance.

The review includes the named PRs, selected source, local workflow syntax, relative file targets in Markdown, and the executed checks in [verification](VERIFICATION_REPORT.md). Complete source review, historical per-run root cause classification and validation of all operational documentation remain incomplete.
