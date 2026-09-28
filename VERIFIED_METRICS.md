# Verified Metrics

This file is the evidence anchor for quantitative claims about this repository.

## Historical main CI baseline

**Code commit:** `a5d39be286a9bac62b01d898ace17607ae058e89`  
**Successful main CI run:** https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/35809388960  
**Verification date:** 2026-09-23

| Claim | Verified value | Evidence |
|---|---:|---|
| Automated tests | **641 passed** | Main CI, Python 3.11 unit-test job; CI also reports 641 tests collected |
| Statement coverage | **79.54%** | Main CI coverage report; gate is 77% |
| Prompt-injection regex patterns | **55** | `src/mcp_monitor/detectors/prompt_injection.py`, `INJECTION_PATTERNS` contains 55 compiled entries |
| Elastic Security rules | **9** | `detection_rules/elastic_rules.toml` contains 9 `[[rule]]` records |
| Core SIEM tests | **21** | `tests/test_siem.py` contains 21 `test_*` functions |
| Additional SIEM scenario-runner tests | **7** | `tests/test_siem_scenarios.py` contains 7 `test_*` functions |

## Claim boundary

These values describe the cited historical CI run, not the local repair. The gateway only governs calls routed through the enforcement path, and heuristic detectors can have false positives and false negatives.

## Current main verification (2026-09-27)

Commit `c68e200` on `main`. `python -m pytest tests --cov=mcp_monitor` completed with
**659 passed** and **82% statement coverage** on Python 3.12. The full GitHub Actions
suite (CI, Production Gate, Documentation Integrity) — including Ruff, Pyright, Bandit,
pip-audit, CodeQL, Trivy, SBOM, Docker build validation, and the Python 3.10/3.11/3.12
matrix plus the Windows control-plane job — passes on this commit. The red-team simulator
module is now covered at 99% (previously 0%).

## Reproduce

Use the repository CI workflow for the authoritative dependency set and Python matrix. For a local check:

```bash
python -m pytest tests/ -q
python -m pytest tests/ --collect-only -q
```

For the two static counts used in résumé/portfolio claims:

- Count `re.compile(...)` entries inside `INJECTION_PATTERNS` for the 55 prompt-injection patterns.
- Count `[[rule]]` records in `detection_rules/elastic_rules.toml` for the 9 Elastic rules.
- Count `test_*` functions in `tests/test_siem.py` for the 21 core SIEM tests.

When implementation or tests change, update this file only after re-running CI and reconciling the public README/portfolio claims.
