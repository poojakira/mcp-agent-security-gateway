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
