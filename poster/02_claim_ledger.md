# Claim Ledger — Phase 1–16 Gateway Poster

> **Reviewed development source:** `43a72c8984bf9a472b9055d4f9e84cc759f61718`, November 11, 2026 UTC. **All references are to an unmerged review stack; PRODUCTION NO-GO.** This ledger replaces the former poster headline based on the older PR #167 synthetic merge.

| Claim | Evidence | Classification and boundary |
|---|---|---|
| 1,211 tests passed and 6 skipped per Python 3.10/3.11/3.12 | [Integration run 42971171992](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42971171992) | CI_VERIFIED_EXACT_HEAD; 6 skips are exclusions, not passes |
| 5/5 integrated jobs passed | Same integrated run | CI_VERIFIED_EXACT_HEAD, not production approval |
| Security hygiene completed | [Hygiene run 42971171965](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42971171965) | CI_VERIFIED_EXACT_HEAD; tracked-file/history regex patterns and configured Bandit scope, not all secrets |
| Installed Python CycloneDX SBOM generated; no known advisories reported | [Supply-chain run 42971171775](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42971171775) | CI_VERIFIED_EXACT_HEAD; public advisories at that time, not image/license/deployment certification |
| Real restricted Docker import and MCP tool-list handshake | [Docker run 42971171991](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42971171991) | LAB_VERIFIED; no-network non-root test, not host-wide interception |
| Three local process-kill effect-journal scenarios | `tests/test_phase16_crash_fencing_process.py` in the exact integrated run | LAB_VERIFIED; not power loss, external providers or distributed consensus |
| Keyless, exact local side-effect permits | `src/mcp_monitor/protocol/effect_authority.py` and dedicated tests | SOURCE_AND_CI_VERIFIED; not independently authenticated human consent |
| Offline production-flagged stdio profile rejects network modes | `src/mcp_monitor/proxy/stdio_proxy.py` and tests | SOURCE_AND_CI_VERIFIED; untrusted agents outside gateway remain out of scope |
| 96-case detector synthetic benchmark, TP40/FN8/FP16/TN32 | `docs/review/PHASE12_BENCHMARK_PROTOCOL.md` | HISTORICAL_AUTHOR_CURATED, not independent or field-performance estimate |
| Universal bypass prevention, verified external bookings, complete remote identity/revocation, TLS/IP/redirect egress, independent pentest or signed release | `PRODUCTION.md` / release candidate evidence document | **NOT VERIFIED — DO NOT CLAIM** |
| No paid provider API key in the cited free offline workflows | Workflow source and reviewed repository configurations | SCOPED_DESIGN; does not prove the absence of all deployed secrets, or eliminate HTTP operator authentication |
| Earlier 1,158-pass/83.10% merge-CI snapshot | [Historical run 42748742036](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42748742036) | HISTORICAL; do not attach its coverage rate to current 1,211-pass source |
| Earlier October 782-pass/81.93% snapshot | [Historical run 38462601803](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/38462601803) | HISTORICAL; separate source and environment |

## Document-integrity rule

Release decision remains **NO-GO**, whatever a workflow or poster is named. Every active numerical claim must include a source commit, run and scope; when inputs change, regenerate the poster and update this ledger. Do not silently treat a historical document as current or confuse a hypothetical attack with an observed exploit.
