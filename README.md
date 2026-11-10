> **License:** New releases are governed by [LICENSE](LICENSE). Earlier MIT-licensed versions retain their historical terms; see [license history](docs/license-history/LICENSE-BEFORE-2026-10-13.txt).

# MCP Agent Security Gateway

**Security research and engineering prototype — development scope: phases 1–16. Not approved for production deployment.**

The gateway inspects supported Model Context Protocol (MCP) / JSON-RPC traffic before selected tool calls reach downstream MCP servers. It combines tool authorization, untrusted-input inspection, scoped exfiltration/egress rules, telemetry, and evidence of downstream outcomes. Only traffic routed through a supported enforcement path is protected. Neither heuristic detectors nor a passing development test establishes universal bypass prevention.

**Repository:** [source and issues](https://github.com/poojakira/mcp-agent-security-gateway) · **Maintainer:** [@poojakira](https://github.com/poojakira) · **Status authority:** [Phase 13 release gate](docs/review/PHASE13_RELEASE_READINESS.md) and [Phases 1–16 integration PR #167](https://github.com/poojakira/mcp-agent-security-gateway/pull/167).

## Architecture

```text
Untrusted agent/client requests
             |
     Supported MCP/JSON-RPC entry point
             |
  framing, duplicate-key and schema checks
             |
  identity + authority + capability checks
             |
  policy, prompt-injection and egress signals
             |
  allow or deny (fail closed where implemented)
             |
  optional durable effect / revocation adapters
             |
      constrained downstream MCP server
             |
  recorded decision, audit trail and effect evidence
```

The HTTP inspection service and stdio proxy have different enforcement and authentication properties. An inspection decision is **not** proof of a downstream side effect. A local, operator-controlled identity is **not** independent authentication. A cooperative revocation lock is **not** distributed revocation. The demonstration dashboard is not the protected production boundary.

## Development record: phases 1–16 only

The original gateway provides JSON-RPC inspection, heuristic injection detection, policy evaluation, capability checks, credential handling, audit chaining, telemetry and controlled stdio forwarding. Research additions in the phase branches include:

| Development scope | Implemented/tested within bounded research scope | Qualification |
|---|---|---|
| Baseline gateway and early hardening | Parser, policy engine, detectors, logging, rate limiting and CI | Older full-suite counts belong to their dated commits |
| Offline isolation and local identity pilots | Restricted Docker, trusted session mapping and offline JWKS/authorization checks | No independent remote-principal or universal routing guarantee |
| Durable authority and egress experiments | SQLite authority records and isolated network-policy pilots | No broad live outbound access-control proof |
| Protocol and effect journal | Multiplexed stdio subset, effect intent/recovery research | No complete protocol interoperability or exactly-once guarantee |
| Synthetic adversarial evaluation | Frozen author-curated fixtures and release-gate checks | Not an independent real-world effectiveness estimate |
| Real MCP and consequence verification | First-party protected MCP subprocess, controlled file effects and SQLite reconciliation | Local/disposable tests; host-level bypass and ambiguous external outcomes remain |
| Cooperative revocation fence | Single-host SQLite lock coordinated with a protected file replacement | Legacy unfenced mode, non-cooperating processes and crash ambiguity remain |

The phase work is largely represented by **draft/unmerged PRs and an integration candidate**, not a production release or automatically merged main-branch feature set. [Integrated candidate PR #167](https://github.com/poojakira/mcp-agent-security-gateway/pull/167) explicitly records remaining production blockers. [Phase 14 evidence](docs/review/PHASE14_BYPASS_DECISION.md) is for an isolated no-network Docker laboratory. Phase 15 and 16 evidence is described in [PR #163](https://github.com/poojakira/mcp-agent-security-gateway/pull/163) and [PR #166](https://github.com/poojakira/mcp-agent-security-gateway/pull/166).

## Security guarantees and non-guarantees

**Demonstrated within specified tests:** deny-before-forwarding on selected policy paths; strict JSON parsing in scoped components; selected real MCP negative cases where denied operations left protected fixture bytes unchanged; local effect reconciliation; and cooperative revocation controls in an experimental adapter, subject to exact-commit verification.

**Not demonstrated as a universal property:** mandatory gateway routing; protection against the host operator or Docker-daemon owner; production IdP identity binding and comprehensive revocation; complete MCP method/transport/cancellation coverage; cross-host effect consistency; production network egress enforcement; external effect rollback; independent adversarial precision/recall; and deployment/release approval.

**Release decision: NO-GO.** Refer to [Phase 13 gate](docs/review/PHASE13_RELEASE_READINESS.md). No count of passing tests overrides outstanding release blockers.

## Install and test locally

Use Python 3.10–3.12 and a disposable development environment:

```bash
git clone https://github.com/poojakira/mcp-agent-security-gateway.git
cd mcp-agent-security-gateway
python -m venv .venv
source .venv/bin/activate  # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e ".[dev,server]"
python -m pytest tests -q
ruff check src tests
ruff format --check src tests
```

These commands are **reproduction instructions**, not a claim that they were run during this documentation revision. Optional tests need their declared extra dependencies and environment. Run scoped security and container suites as documented in the [runbook](RUNBOOK.md); inspect exact-head CI, rather than adding results from different branches.

## Evidence interpretation

The baseline [metrics file](VERIFIED_METRICS.md) reports **782 tests and 81.93% statement coverage** for a specifically identified October 13, 2026 Linux CI commit. This is a **historical snapshot, not the integrated phase branch's current test total**. Likewise, the **69 named signatures** are a source inventory, not measured detection accuracy. Older poster figures, synthetic classification results, local timing microbenchmarks and branch-specific test counts must retain their exact dates, configurations and denominators. Never represent them as production outcomes.

## Documentation

- [Security reporting and credential handling](SECURITY.md)
- [Threat model and trust boundaries](THREAT_MODEL.md)
- [Security audit — dated historical findings](SECURITY_AUDIT.md)
- [Development and incident runbook](RUNBOOK.md)
- [Operating contract and release restrictions](PRODUCTION.md)
- [Evidence and benchmark limitations](VERIFIED_METRICS.md)
- [Phase 13 integrated security gate](docs/review/PHASE13_RELEASE_READINESS.md)
- [Phase 14 bounded bypass assessment](docs/review/PHASE14_BYPASS_DECISION.md)
- [GitHub review candidate for phases 1–16](https://github.com/poojakira/mcp-agent-security-gateway/pull/167)

## Research poster

[View existing research poster PDF](poster/poster_36x48.pdf). This older poster is **historical and does not verify the integrated phase 1–16 candidate**. Do not use its figures without their printed dates and source commits.

## Security and data handling

Never commit credentials or real user data. Obtain keys only from operator-controlled environment/secret facilities when required. Do not reuse public demonstration credentials. Deleting a secret from source **does not revoke it**; revocation must occur at the credential issuer. Use disposable offline experiments for unauthorized-tool, malformed-payload and file-effect testing.

## License

See [LICENSE](LICENSE) and the [historical license terms](docs/license-history/LICENSE-BEFORE-2026-10-13.txt).
