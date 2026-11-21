# Verification report

**LOCAL ONLY.** Tested source: d36104752fb4877d9a558e086184a08e16da756c. Fixing source at report time: 31758f467f8d17ef500f1e0f2c09c22f1814aa23. Hosted observations in [audit findings](AUDIT_FINDINGS.md) identify their separate source SHAs.

Docker Python 3.12.16. Install requirements-workbench-test.txt and editable dev extras. Run Ruff, pytest with pytest-cov and the 77% gate, followed by the isolated wheel smoke. Runtime and browser transport proof beyond this suite remains open.

Ruff check and format passed. 834 tests passed, 0 failed, 0 skipped, 81.79684880992289% coverage in 100.18 seconds. Wheel build and a separate installed-wheel Elastic rules smoke both exited 0. An archive-only baseline attempt found missing installed rule data. Command log: mcp-agent-security-gateway.verified-check.log.

- exit=0

The local workflow syntax check used actionlint 1.7.7. The Markdown lexical check inspected relative file targets. It does not establish heading fragments, external targets, or example commands. Logs and command wrappers are in the workspace audit directory.
