# Research Brief — Poster 01

> Evidence status: The Markdown companion below is refreshed to the latest verified code snapshot. The rendered poster PDF keeps its own printed historical commit/date and must not be read as proof of newer metrics.

## Repository
`github.com/poojakira/mcp-agent-security-gateway` (public, default branch `main`, primary language Python).
Latest verified code snapshot: `cbdf733858d186bb4d72ca57a9c10e74ee84dd65` (successful CI and Production Gate).

## Academic Project Title
**Runtime Policy Enforcement at the AI Agent-to-Tool Boundary**

## Technical Subtitle
Design and Validation of an Inline MCP/JSON-RPC Security Gateway

## One-Sentence Contribution
An application-layer inspection and authorization point for agent-generated MCP `tools/call` requests that combines JSON-RPC parsing, argument normalization, capability/trust checks, heuristic content detectors, policy evaluation, and hash-chained auditable telemetry — with an evidence policy that separates local verification from historical CI and makes no production guarantee.

## Problem Statement
LLM-based agents translate untrusted natural-language context into structured tool invocations. Once an agent can call tools, a manipulated prompt can influence file access, outbound requests, process-execution intent, or privileged service calls. Model-level safety alignment does not necessarily inspect the *resulting structured tool invocation* at the point where it becomes executable. There is no inspection or authorization boundary between the agent's decision and the downstream MCP server that will act on it.

## Motivation
The Model Context Protocol (MCP) standardizes how agents call tools over JSON-RPC. The transport is well-specified; the *security posture of individual tool calls* is not. A security team that wants to test, inspect, or measure this boundary before trusting it currently has no reproducible reference control. This project builds one and, importantly, documents exactly what it does and does not enforce.

## Threat Model
- **Adversary:** malicious prompt author, compromised MCP server, or rogue agent producing manipulated `tools/call` requests. Also considered: network attacker (MITM) and insider with log access.
- **Attacker capability:** can craft tool-call arguments (prompt-injection content, PII exfiltration payloads, process-spawn strings, disallowed egress destinations); can attempt malformed/ambiguous JSON-RPC; can flood detectors.
- **Attack vector:** the `tools/call` request itself and, bidirectionally, tool outputs.
- **Protected asset:** downstream tool/server actions and the integrity of the security audit trail.
- **Trust boundary:** the gateway process sits between the untrusted zone (prompts, agent decisions, tool args/outputs, external servers) and the trusted zone (policy engine, audit log, config).
- **Assumptions:** only traffic routed through the gateway can be inspected; the integrating runtime honors returned allow/deny decisions.
- **Out of scope:** OS/kernel isolation, packet-level network firewalling, complete DLP, guaranteed prompt-injection prevention.
- **Residual risk:** heuristic detectors have false positives and false negatives; enforcement outside the routed path is not covered.

## Research / Engineering Question
> Can agent-generated MCP tool invocations be parsed, normalized, and policy-evaluated before reaching downstream tools while producing tamper-evident security evidence — and what does that control provably enforce versus not?

## Objective
Determine whether an inline application-layer gateway can inspect and authorize MCP `tools/call` requests at the agent-to-tool boundary under the stated assumptions, with reproducible test evidence.

## Engineering Sub-Objectives
- **O1** — Parse and validate JSON-RPC, rejecting malformed/ambiguous/duplicate-key and deeply nested payloads before forwarding.
- **O2** — Normalize obfuscated argument content (Unicode/zero-width/homoglyph/BiDi, Base64/ROT13) prior to inspection.
- **O3** — Evaluate trust/capability (server registry, allow-list) and content signals (prompt injection, PII, exfiltration, process-spawn, egress).
- **O4** — Emit tamper-evident evidence (SHA-256 hash-chained audit log + WAL) and ECS-formatted events for a local detection lab.

## Architecture
Agent/MCP client → inline stdio proxy **or** FastAPI control plane → parse/normalize → trust+capability checks → content/policy signals → allow/block decision → audit+telemetry → downstream MCP server. Enforcement semantics differ by integration path (stdio proxy vs HTTP control plane vs Python wrapper that raises `ToolBlocked`).

## Methodology
1. Receive `tools/call` over JSON-RPC (single or batch).
2. Parse/validate structure; reject malformed/ambiguous input.
3. Normalize potentially obfuscated argument content.
4. Evaluate server-registry/capability trust checks.
5. Run heuristic detectors (55 prompt-injection patterns, PII, exfiltration, shadow-server, process/egress).
6. Evaluate policy → allow/block decision (circuit-breaker path fails closed to DENY).
7. Record hash-chained audit + WAL; format ECS events for the detection lab.

## Evaluation Method
Correctness/behavior validation via the repository's automated test suite with statement coverage, executed in a clean local environment. Static counts (patterns, rules, SIEM tests) verified by importing the module and counting committed rule records. Historical validation preserved from a prior main-branch CI run. No production/latency SLO is claimed.

## Current Repository Evidence
GitHub Actions, Python 3.12, code snapshot `cbdf733858d186bb4d72ca57a9c10e74ee84dd65`:
- **707 tests passed**, 0 failed.
- **82.84% statement coverage** (5,337 statements, 916 missed).
- The same test suite is green on Python 3.10 and 3.11.
- **55** entries in `INJECTION_PATTERNS`.
- **9** Elastic `[[rule]]` records.
- **21** core SIEM tests plus **12** SIEM scenario-runner tests.
- CI also passed Ruff/formatting, Pyright, security scan, CodeQL, Windows control-plane checks, and Docker build.

The gateway additionally supports stable multi-credential authentication, trusted source-address selection, IPv4/IPv6 canonicalization, and locally generated HMAC-SHA256 credential/network fingerprints without exporting raw credentials or raw source addresses. External validation pilot completion is **not** claimed.

## Historical Evidence (validation snapshot — not current checkout)
Main CI run `35809388960`, commit `a5d39be`, dated 2026-09-23: **641 passed** and **79.54% coverage**. Keep it labeled as a historical snapshot; newer verification is listed in the current-repository evidence section above.

## Important Negative Results / Honest Findings
- Coverage is uneven: `server/realtime.py` 36%, `siem/shipper.py` 53%, `production/server.py` 65%, and `production/identity_telemetry.py` 81%; aggregate coverage is 82.84%.
- Detection is heuristic — no measured false-positive/false-negative rate on an external corpus is established by this repo.
- Enforcement behavior is **not** identical across the stdio proxy, HTTP control plane, and Python wrapper paths.

## Contribution
A reproducible, test-backed reference implementation of an inspection+authorization boundary for MCP tool calls, notable less for novel detection than for its **evidence discipline**: it separates historical CI from local runs and explicitly enumerates what it does not protect.

## Limitations
1. Only traffic routed through the gateway can be inspected or blocked.
2. Pattern/heuristic detection cannot guarantee identification of all attacks; no external FP/FN rate measured.
3. Enforcement is external — the integrating runtime must honor decisions; semantics differ per path.
4. Local test success is not operational reliability; no production deployment evidence.
5. Aggregate coverage masks lower-coverage runtime modules such as the realtime server, SIEM shipper, production server, and new credential/network telemetry helper.

## Future Work
Larger external adversarial corpus with measured FP/FN; unify enforcement semantics across paths; raise coverage on lower-coverage runtime modules; complete external credential-behavior telemetry contract/pilot validation; validate against a real MCP ecosystem; independent reproducibility study; performance benchmarking published as environment-scoped baselines (not SLOs).

## Reproducibility
```
git clone https://github.com/poojakira/mcp-agent-security-gateway.git
cd mcp-agent-security-gateway
python -m venv .venv && .venv\Scripts\Activate.ps1
python -m pip install -e ".[dev,server]"
$env:PYTHONPATH="src"; python -m pytest tests -q --cov=mcp_monitor --cov-report=term
```
Evidence artifacts: `evidence/mcp_replay_evidence.json`, `VERIFIED_METRICS.md`, `detection_rules/elastic_rules.toml`.

## References
1. Anthropic. "Model Context Protocol (MCP) Specification." modelcontextprotocol.io.
2. JSON-RPC 2.0 Specification. jsonrpc.org.
3. OWASP. "Top 10 for Large Language Model Applications" (incl. LLM01 Prompt Injection). owasp.org.
4. MITRE ATLAS. Adversarial Threat Landscape for AI Systems. atlas.mitre.org.
5. NIST AI 100-1. "Artificial Intelligence Risk Management Framework (AI RMF 1.0)." 2023.
6. Elastic Common Schema (ECS) Reference. elastic.co.
