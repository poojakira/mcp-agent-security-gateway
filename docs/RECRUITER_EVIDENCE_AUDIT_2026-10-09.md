# Recruiting evidence audit, 2026-10-09

This document separates bounded repository evidence from unverified production impact.

| Project | Verified 2026 CI snapshot | Boundary |
|---|---|---|
| MCP Agent Security Gateway | 723 passing tests, 81.91% statement coverage; 55 prompt-injection patterns; 9 Elastic rules; 21 core SIEM tests | Not production incident-response MTTR or universal blocking |
| AWS Agent Identity Guard | 25 deterministic rule IDs; 243 collected, 240 passed, 3 skipped | Static IAM analysis; not effective AWS permissions or a measured reduction in actual roles |
| HF Model Provenance Scanner | 241 passed, 1 skipped, 75.67% coverage; 33/33 committed adversarial fixtures detected | Curated test cases, not universal detection |

Controlled experiments: 10/10 selected unauthorized gateway calls and 4/4 injected detector errors blocked on tested enforcement paths. An artificial 50-ms polling comparison yielded 96.15% shorter interval, NOT human incident response time. IAM static findings dropped from 89 to 46 (48.3%) in example policies, NOT live role reductions. Never claim 40% faster manual IAM review, 60% greater HF detection coverage, or 100% protection from malicious model code without audited comparisons.

MCP CI historical growth: 622 to 723 tests (+16.2%); 78.41% to 81.91% statement coverage (+3.50 percentage points); measured source statements 4,679 to 5,644 (+20.6%). The different snapshots are not an incident outcome measure.

AEROSEC's $120K is a proposed first-year commercialization scenario, not funded revenue. ASU teaching workload figures, experience dates and project development dates are candidate-supplied, not independently verified by GitHub. Portfolio notes original project start dates predate public GitHub commit history.

Authoritative files: each repository's VERIFIED_METRICS.md; MCP docs/ENFORCEMENT_BENCHMARK_2026-10-09.md; HF evidence/DETECTION_PROOF.md; and the portfolio's tracked LaTeX/TypeScript resume.
