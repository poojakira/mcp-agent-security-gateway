# Controlled enforcement benchmark (2026-10-09)

The regression benchmark is executed by `python benchmarks/enforcement_regression.py` and compares fixed attack and benign fixtures. It intentionally disables the optional ML second pass for deterministic testing.

**Claim boundary:** This is a small, previously used, hand-picked fixture set. It cannot demonstrate real-world prompt-injection recall, high-confidence precision, production reliability, or reduced incident-response time. The local detection execution time does **not** measure incident response (MTTD/MTTR). A zero false-positive count on eight clean fixtures is not evidence of a population-level false-positive rate below 1%.

The root cause was a split between positive injection matches and a separate threshold used to enforce the decision. The monitor now blocks when its detector returns a positive match. This favors stopping recognized attacks and may increase false positives on legitimate instructions, especially when source material is quoted in tools or documentation. Evaluate representative benign corpora and an independent held-out attack set before production adoption. Do not imply that 100% blocking on a known fixture set generalizes to adversarial traffic.

The IAM analyzer remains a static linter; real percentages of remediated over-privileged roles require snapshots of actual roles, valid least-privilege fixes, and post-fix rescanning. Do not count denying *all* permissions as valid remediation.
