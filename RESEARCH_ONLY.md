# Research lane — do not deploy

**Branch role:** experimental adversarial measurement, detector evaluations, and future MCP indirect-injection research. This branch is NOT the approved offline release candidate and MUST NOT be merged directly into `main`.

The only three ongoing branch *roles* for this project are:

- `main`: stable published baseline; scoped fixes must pass review and CI.
- `release/phase1-16-offline-rc-20261111`: offline-only first-party MCP manifest enforcement candidate, pending review and production NO-GO.
- `research/phase1-16-adversarial-20261111`: this isolated, deliberately experimental detector benchmark.

## Frozen diagnostic evidence

Original author-curated 96-case synthetic tests: 40 TP, 8 FN, 16 FP, 32 TN. These cannot be generalized as field efficacy.

Separately authored pinned 303-case public benchmark: 200 labeled injections and 103 benign; regex-only TP28/FN172/FP0/TN103; bundled local hybrid TP64/FN136/FP0/TN103. These are **prompt labels, not demonstrated MCP action or exfiltration successes**.

Source upstream `stef41/prompt-injection-benchmark` commit `dc0072ad6af8d1be049cdb60959e3ff51df4bcae` and blob hash `17d2c521a6b7a5ebd7f68e768fd334cd97897a4e`; [original green evaluation](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43134911328). Do not contaminate this dataset by tuning to it and claiming independent testing.

No third-party provider API keys or paid inference services are required. Public CI downloads a pinned CSV over HTTPS for diagnostic evaluation; this does NOT turn the gateway into a network-enabled production system.

**Production: NO-GO.** Host bypass isolation, external identity, side-effect reconciliation and independent penetration test sign-off remain unresolved.
