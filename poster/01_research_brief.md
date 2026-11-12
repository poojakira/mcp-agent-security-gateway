# Research Brief — Offline MCP Agent Security Gateway (Phase 1–16)

> **Evidence cutoff: 2026-11-11 UTC. DEVELOPMENT RESEARCH ONLY — PRODUCTION NO-GO.** Source: stacked draft PRs #167 and #169–#178; exact verified integration head `43a72c8984bf9a472b9055d4f9e84cc759f61718`. The four named workflows below passed on that head. This does not certify a merged release, a live environment, or safety for ticketing, payments or healthcare.

## Repository

github.com/poojakira/mcp-agent-security-gateway · unmerged Phase 1–16 development stack

## Academic Project Title

Constrained MCP Agent-to-Tool Enforcement with Explicit Release Boundaries

## Technical Subtitle

Local Offline Research Gateway · Exact-Head CI Evidence · November 2026

## One-Sentence Contribution

A constrained agent-to-tool gateway demonstrating explicit MCP capability decisions, scoped untrusted-input inspection, operator-approved local file effects, durable uncertain-outcome tracking and offline Docker containment, with all production claims held behind an unpassed release gate.

## Problem and Threat Model

- Untrusted documents, prompts and tool metadata can influence an agent toward unauthorized actions.
- MCP JSON-RPC tool calls can cause effects, while source inspection cannot stop a separate direct host, browser or network path.
- An allowed tool's success response is not proof of an independently observed external effect.
- The verified target is a disposable local manifest adapter, not arbitrary external websites or paid providers.

## Method

1. Parse supported JSON-RPC framing and reject ambiguous or unauthorized requests in hardened mode.
2. Intersect tool discovery and calls with exact, trusted capability allowlists.
3. Inspect selected untrusted inputs with signatures; do not treat detection as the authorization boundary.
4. Require a trusted local exact-operation permit before configured side-effect tools in hardened mode.
5. Restrict production-flagged stdio startup to a pinned, offline Docker image; verify a real protected server Docker handshake.
6. Reserve an operation durably and report uncertain outcomes on interrupted effects; independently inspect a local manifest, not remote-provider results.

## Current Verified Evidence

- **1,211 passed, 6 skipped** per Python version (3.10, 3.11, 3.12), exact source commit `43a72c8984bf9a472b9055d4f9e84cc759f61718`; 5/5 integration jobs passed.
- **Four workflows passed on the same commit**: integrated security, Security Hygiene, Python supply-chain evidence, protected Docker import/handshake.
- Real child-process termination tests exercised before reservation, after reservation and after a local approved file change but before acknowledgment. This is not physical power-loss testing.
- A CycloneDX SBOM for the installed Python CI environment was generated and retained as an Actions artifact; `pip-audit` reported no known advisories in that environment at that time.
- Real protected-server Docker import and `tools/list` handshake passed under a no-network, non-root, read-only-root profile.

## Integration Validation

- Selected focused tests exercise tool-discovery filtering, malformed egress hints, strict constructor mode, trusted local effect permits and synthetic process-crash reconciliation.
- The prior 96-case author-curated regex benchmark recorded TP=40, FN=8, FP=16, TN=32. No independent field efficacy is claimed.
- Prior inventory counted 69 named injection signatures and 9 Elastic rule records. These are source counts, **not** protection rates or production deployments.
- The cited CI checks use free tooling and no operator-provided paid provider API keys; this cannot prove that every external deployment contains no credentials.

## Honest Boundaries

- **PRODUCTION NO-GO.** Draft PRs remain unmerged; a passing CI check is necessary but not sufficient.
- No general non-bypassability against a host/Docker administrator or unrelated browser/process is established.
- Network-enabled DNS/IP/port/redirect enforcement is not certified. The tested offline profile denies networking instead.
- Local identity pilots and operator permits are not independently authenticated external tenant/user consent.
- External bookings, payments and remote side effects are not verified or reconciled. Process-kill tests are not real power-loss/distributed tests.
- No independent penetration test, blinded representative benchmark, deployed-secret inventory, confirmed live revocation or human release sign-off exists.

## Release Decision

- **NO-GO for production; APPROVED USE CLAIM LIMITED TO disposable, offline, non-sensitive development experiments.**
- A production decision requires deployment-specific routing, identity, egress and recovery testing; independent adversarial review; complete supply-chain and secret lifecycle assurance; and accountable human authorization.
- Do not combine historical October or November test counts with the latest source head.

## Reproducibility

Exact source `43a72c8984bf9a472b9055d4f9e84cc759f61718`; [full matrix](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42971171992), [hygiene](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42971171965), [SBOM](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42971171775), [Docker](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42971171991). See poster/13_reproducibility.md.

## Evidence Sources

- GitHub Actions exact-head runs: 42971171992, 42971171965, 42971171775 and 42971171991.
- `src/mcp_monitor/proxy/stdio_proxy.py`, `src/mcp_monitor/protocol/effect_authority.py`, `src/mcp_monitor/protocol/effect_journal.py`.
- `src/mcp_monitor/protected_repo_server.py` and `Dockerfile.protected-mcp`.
- `docs/review/PHASE1_16_RELEASE_CANDIDATE_NO_GO_20261110.md`, `PRODUCTION.md`.
- `poster/02_claim_ledger.md` with claim-level status and limitations.

## References

Model Context Protocol; JSON-RPC 2.0; OWASP guidance for LLM applications; NIST AI RMF. Reference names alone are not compliance certifications.
