# Phase 12 additional public-corpus detector stress test — 2026-11-11 (Phoenix time)

> **PRODUCTION NO-GO.** This new external-source diagnostic is independent of the original *author-curated 96 cases*, but it is not an independently executed penetration test or a representative measure of real MCP attack success.

## Reproducibility / source provenance

- External dataset: [stef41/prompt-injection-benchmark](https://github.com/stef41/prompt-injection-benchmark), MIT license claimed by the upstream README.
- Immutable upstream commit: `dc0072ad6af8d1be049cdb60959e3ff51df4bcae`.
- Fetched `data.csv` verified by `git hash-object`: `17d2c521a6b7a5ebd7f68e768fd334cd97897a4e`.
- Local free GitHub Actions CI: [public-corpus diagnostic run #43134911328](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43134911328), latest tested source `34210cd62b8568192ea65cf48c230dfba2048534`.
- Dataset contains **303 actual CSV rows: 200 labeled injection, 103 benign**. The upstream README describes 100 benign rows, which **disagrees with the checked actual artifact**; use the parsed source, not the README, for denominators.
- Deterministic `benchmark.external_public_eval`, same input field (`read_document.arguments.content`) in both modes. Local scikit-learn training uses existing bundled repo corpus, no external model service or API key; no tuning was performed against this external CSV.
- Full per-category confusion matrix and error indices are retained as GitHub Actions artifacts for 7 days.

## Measured result — external 303-case corpus

| Classifier mode | True positives | False negatives | False positives | True negatives | Recall | FPR | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Regex-only (existing default proxy setting) | 28 | 172 | 0 | 103 | **14.0%** | **0.0%** | 24.56% |
| Regex + bundled local TF-IDF classifier | 64 | 136 | 0 | 103 | **32.0%** | **0.0%** | 48.48% |

The apparently perfect precision is a result of zero false positives **on these 103 benign cases only**. It does not predict deployment precision. In particular, the original 96-case author-curated Phase 12 synthetic benchmark recorded **16 false positives** and **8 misses** (TP40, FN8, FP16, TN32); the datasets are different and must **not** be averaged or compared as though drawn from the same distribution.

## Autopsy

- **Confirmed weakness:** Both regex-only and optional local ML miss most malicious labels on this independently authored prompt-oriented corpus. Their strong self-curated Phase 12 metrics do not generalize to this dataset.
- **Competing interpretation:** This corpus contains direct user prompts, not only untrusted MCP document/tool-return payloads. The label represents author-defined prompt injection, *not* whether the proposed operation had sufficient authorization or any exfiltration occurred. Treat this as diagnostic failure evidence, not an attack-success probability.
- **Action:** Do NOT change safety policies or silently promote the optional local ML as a complete solution. Keep trusted identity/tool allowlists, host-level isolation, content-origin separation and independent consequence observation as the primary authorization controls.
- **Next gate:** Obtain a representative, task-conditioned MCP injection benchmark with independently labeled benign security documentation, adversarial indirect tool descriptions, malicious downloads, encoding and legitimate quoted attacks. Freeze a separate holdout BEFORE tuning. Report work cost, latency and false-positive impact. Do not claim production detector efficacy until validated.

**Release decision:** Detector generalization is **NOT FIXED**; Phase 1–16 production remains NO-GO. This diagnostic used only free software and public HTTP access without provider API keys.
