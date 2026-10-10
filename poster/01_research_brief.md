# Research Brief - Poster 01

> Evidence status: Refreshed against code snapshot `008775c8878cc70c50247baa223da3256e093316` and successful GitHub Actions CI run `37184196303` on 2026-09-30. The quantitative claims below are tied to that code snapshot. Do not generalize benchmark or test results beyond their stated scope.

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

GitHub Actions CI on Python 3.12 at the poster snapshot `008775c8878cc70c50247baa223da3256e093316` reports:

- **723 tests passed**, 0 failed.
- **81.91% statement coverage** - 5,644 statements, 1,021 missed.
- The Python 3.10 and 3.11 test jobs also completed successfully.
- Ruff/format, Pyright, Bandit, pip-audit, CodeQL, Windows control-plane validation, container build, Trivy/Grype/SBOM jobs completed successfully.
- **55** entries remain in the named prompt-injection pattern collection.
- **9** Elastic `[[rule]]` records.
- **21** core SIEM tests plus **12** SIEM scenario-runner tests.

## October 2026 detector update (separate from the cited historical CI snapshot)

Commit `c30075da1dc1d3fa7b843bb76be8e842fbfa6ae3` merged the detector-only changes from PR #123. The named runtime prompt-injection signature list now has **69 entries (55 historical plus 14 added)**. The focused local regression run passed **77 tests**. On 15 *development* attack examples, the updated regex-only detector flagged **15/15**, while it also flagged **3/15** benign examples. This is a test-set result, **not** independently held-out recall, population-level precision, or a customer-deployment efficacy percentage.

A separate five-case synthetic policy-enforcement check denied 5/5 disallowed calls against a deliberately pass-through comparator, **not** a measured reduction in incidents or unauthorized execution attempts in the field. A comparison of the earlier 12-signature and 55-signature detectors on 15 familiar positive fixtures found **0 percentage-point recall difference**, because both detected all 15. The 14 additional signatures have not been independently validated against unseen data. The IAM Guard's five-case synthetic check detected 5/5 deliberately vulnerable cases, but also produced a finding on one nominally benign read policy (AIG007); it is **not** evidence of general IAM recall or precision.

The Cerberus pilot, persistent identities, baseline, deployment and transport configuration are not involved in these measurements. Do not combine the 69-entry runtime detector with the older 55-entry verified snapshot, and do not combine the original 81.91% code coverage figure with the later 752-test Docker run.

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
git checkout 8427f9ecafd3438a86775a7ceaf809f4ee051b5b
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev,server]"
$env:PYTHONPATH="src"
python -m pytest tests -q --cov=mcp_monitor --cov-report=term
```

Expected at the cited snapshot: **723 passed**, **81.91%** statement coverage.

## Evidence Sources

- GitHub Actions CI run `37184196303`
- `VERIFIED_METRICS.md`
- `evidence/mcp_replay_evidence.json`
- `detection_rules/elastic_rules.toml`
- `tests/test_siem.py`
- `tests/test_siem_scenarios.py`

## References

Model Context Protocol specification; JSON-RPC 2.0; OWASP guidance for LLM applications; MITRE ATLAS; NIST AI RMF; Elastic Common Schema.
