# Phase 12 — Frozen adversarial synthetic baseline

96 author-curated, balanced cases: 48 malicious and 48 benign, in
12 families. The cases were committed separately before evaluation.
Only the repository's PromptInjectionDetector regex-only implementation
is evaluated, with enable_ml=False. No detector tuning is permitted.

Results must report TP/FP/FN/TN, precision, recall, FPR, FNR and F1,
family-level results, all error IDs and the corpus SHA-256.

**Critical limitation:** This is not an independent, externally validated,
blinded or representative real-world benchmark. Hard benign negatives
include quoted malicious text and security-research descriptions. This
evaluation cannot establish full gateway protection, optional ML efficacy,
or production security. No paid services, live test targets, external
network services, user data or production deployments.

Production-security gate remains OPEN. Keep parent PRs draft/unmerged.

## Verified first milestone: baseline evaluation

**Evaluated source commit:** `d122a883ea534ee2f68b13aaecc9fa33c9016904`.
**GitHub Actions:** [run #42544631574](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42544631574), completed successfully on Python 3.10, 3.11 and 3.12 (**3/3 jobs**).
The 96 labels were committed on commit `e6dc1ef9465f79d530472706ac00d0f49b8f748e` before the first evaluation.

| Metric | Result |
|---|---:|
| Malicious synthetic cases | 48 |
| Benign synthetic cases | 48 |
| True positives | 40 |
| False negatives | 8 |
| False positives | 16 |
| True negatives | 32 |
| Precision | 71.43% |
| Recall | 83.33% |
| False-positive rate | 33.33% |
| False-negative rate | 16.67% |
| F1 | 76.92% |

**Observed failures:** 7 of the 8 false negatives come from
`malicious/novel_indirect`, indicating poor generalization to implicit
authority-promotion instructions. The remaining false negative comes from
another malicious family. All 8 quoted attack-text *benign* cases were
classified as malicious. Four benign security-review examples and two benign
Unicode cases also triggered false positives.

These examples were intentionally difficult and curator-labeled. They show
limitations of pattern-based detection **on this dataset only**, not estimates
of the probability of successful compromise or false alarms in production.

**Reproducibility and regression evidence:** the checked-in script records
corpus SHA-256, family breakdown and every failure case ID in the CI output.
The full repository suite passed **1,083 tests with 3 skipped** per Python version;
coverage was **83.10%** (3.10) and **83.07%** (3.11/3.12).
Ruff lint and formatting and 7 dedicated benchmark integrity tests passed
on all three versions.

**Exit decision:** Phase 12 synthetic regex-detector baseline milestone:
**COMPLETE AND VERIFIED**. The originally proposed **independent adversarial
benchmark**, full layered gateway evaluation, optional ML evaluation and
production-security gate remain **OPEN**. No detector rules were adjusted to
improve this score. PR #158 stays draft and unmerged.
