# Research Brief - Poster 01

> Evidence status: Refreshed against code snapshot `f1f226feb0d527f27b90081806d7e9bd90ba0574` and successful GitHub Actions CI run `38502413461` on 2026-10-14 UTC. The quantitative claims below are tied to that code snapshot. Do not generalize benchmark or test results beyond their stated scope.

## Repository

`github.com/poojakira/mcp-agent-security-gateway` - public, default branch `main`.

## Academic Project Title

**Runtime Policy Enforcement at the AI Agent-to-Tool Boundary**

## Technical Subtitle

Design and Validation of an Inline MCP/JSON-RPC Security Gateway

## One-Sentence Contribution

An application-layer inspection and authorization point for agent-generated MCP `tools/call` requests that combines JSON-RPC validation, normalization, trust/capability checks, heuristic content detection, policy evaluation, and tamper-evident audit telemetry before downstream tool execution.

## Problem and Threat Model

LLM agents can turn untrusted natural-language context into structured tool calls with file, process, network, or privileged-service effects. The gateway protects the agent-to-tool boundary only when traffic is routed through it. Attackers may craft malicious tool arguments, malformed JSON-RPC, obfuscated prompt-injection strings, exfiltration payloads, or abusive request patterns.

## Method

1. Parse and validate JSON-RPC, including duplicate-key and malformed-input rejection.
2. Normalize potentially obfuscated content before inspection.
3. Evaluate server trust, capabilities, and content/policy signals.
4. Return allow/block decisions using path-specific enforcement semantics.
5. Record hash-chained audit evidence and SIEM-oriented telemetry.

## Verified Evidence at Cited Snapshot

GitHub Actions CI on Python 3.12 at the poster snapshot `f1f226feb0d527f27b90081806d7e9bd90ba0574` (CI run `38502413461`) reports:

- **782 tests passed**, 0 failed.
- **81.93% statement coverage** - 5,657 statements, 1,022 missed.
- The Python 3.10 and 3.11 test jobs also completed successfully.
- Ruff/format, Pyright, Bandit, pip-audit, CodeQL, Windows control-plane validation, container build, Trivy/Grype/SBOM jobs completed successfully.
- **69** entries remain in the named prompt-injection pattern collection.
- **9** Elastic `[[rule]]` records.
- **21** core SIEM tests plus **12** SIEM scenario-runner tests.

## October 2026 detector update (now merged into main)

The 69-entry named runtime prompt-injection signature list is the current main-branch implementation at commit `f1f226feb0d527f27b90081806d7e9bd90ba0574`. The full CI run `38502413461` validates all 782 tests against this implementation. On 15 *development* attack examples, the updated regex-only detector flagged **15/15**, while it also flagged **3/15** benign examples. This is a test-set result, **not** independently held-out recall, population-level precision, or a customer-deployment efficacy percentage.

A separate five-case synthetic policy-enforcement check denied 5/5 disallowed calls against a deliberately pass-through comparator, **not** a measured reduction in incidents or unauthorized execution attempts in the field. A comparison of the earlier 12-signature and 55-signature detectors on 15 familiar positive fixtures found **0 percentage-point recall difference**, because both detected all 15. The 14 additional signatures (beyond the earlier 55) have not been independently validated against unseen data. The IAM Guard's five-case synthetic check detected 5/5 deliberately vulnerable cases, but also produced a finding on one nominally benign read policy (AIG007); it is **not** evidence of general IAM recall or precision.

The Cerberus pilot, persistent identities, baseline, deployment and transport configuration are not involved in these measurements. Do not combine the 69-entry runtime detector count with older snapshot counts, and do not combine coverage figures across different CI runs.

## Honest Boundaries

- No external population-level false-positive/false-negative rate is established.
- Synthetic correlation fixtures and local microbenchmarks are not production efficacy or SLO evidence.
- Enforcement semantics are not identical across every integration path.
- Only traffic routed through the gateway can be inspected or blocked.
- A successful CI suite is not evidence of a live production SOC deployment.

## Reproducibility

```powershell
git clone https://github.com/poojakira/mcp-agent-security-gateway.git
cd mcp-agent-security-gateway
git checkout c75c52db
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev,server]"
$env:PYTHONPATH="src"
python -m pytest tests -q --cov=mcp_monitor --cov-report=term
```

Expected at the cited snapshot: **782 passed**, **81.93%** statement coverage.

## Evidence Sources

- GitHub Actions CI run `38502413461`
- `VERIFIED_METRICS.md`
- `evidence/mcp_replay_evidence.json`
- `detection_rules/elastic_rules.toml`
- `tests/test_siem.py`
- `tests/test_siem_scenarios.py`

## References

Model Context Protocol specification; JSON-RPC 2.0; OWASP guidance for LLM applications; MITRE ATLAS; NIST AI RMF; Elastic Common Schema.