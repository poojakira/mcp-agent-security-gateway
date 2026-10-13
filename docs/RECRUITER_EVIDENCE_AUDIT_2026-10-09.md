# Recruiting evidence audit, 2026-10-09

This document separates bounded repository evidence from unverified production impact.

| Project | Verified 2026 CI snapshot | Boundary |
|---|---|---|
| MCP Agent Security Gateway | 782 passing tests, 81.93% statement coverage (Oct 13 2026 CI [38462601803](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/38462601803)); 69 named detector signatures; 9 Elastic rules; 21 core SIEM tests | Not production incident-response MTTR or universal blocking |
| AWS Agent Identity Guard | 25 deterministic rule IDs; 247 collected, 244 passed, 3 skipped (Oct 13 2026 CI [38462296804](https://github.com/poojakira/aws-agent-identity-guard/actions/runs/38462296804)) | Static IAM analysis; not effective AWS permissions or a measured reduction in actual roles |
| HF Model Provenance Scanner | 260 passed, 1 skipped, 6 subtests, 75.67% coverage (Oct 13 2026 CI [38462464074](https://github.com/poojakira/hf-model-provenance-scanner/actions/runs/38462464074)); 33/33 committed adversarial fixtures detected | Curated test cases, not universal detection |

Controlled experiments: 10/10 selected unauthorized gateway calls and 4/4 injected detector errors blocked on tested enforcement paths. An artificial 50-ms polling comparison yielded 96.15% shorter interval, NOT human incident response time. IAM static findings dropped from 89 to 46 (48.3%) in example policies, NOT live role reductions. Never claim 40% faster manual IAM review, 60% greater HF detection coverage, or 100% protection from malicious model code without audited comparisons.

MCP CI growth: 622 to 782 tests; 78.41% to 81.93% statement coverage; measured source statements 4,679 to 5,657. Current anchor: Oct 13 2026 CI. The different snapshots are not an incident outcome measure.

AEROSEC's $120K is a proposed first-year commercialization scenario, not funded revenue. ASU teaching workload figures, experience dates and project development dates are candidate-supplied, not independently verified by GitHub. Portfolio notes original project start dates predate public GitHub commit history.

Authoritative files: each repository's VERIFIED_METRICS.md; MCP docs/ENFORCEMENT_BENCHMARK_2026-10-09.md; HF evidence/DETECTION_PROOF.md; and the portfolio's tracked LaTeX/TypeScript resume.

