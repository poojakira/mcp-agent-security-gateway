# Verified Metrics

This file is the evidence anchor for quantitative claims about this repository.

## Verified baseline

**Code commit:** `0f25219d0f20521382819654f8a267202febe304`  
**Successful main CI run:** https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/35158937752  
**Verification date:** 2026-09-16

| Claim | Verified value | Evidence |
|---|---:|---|
| Automated tests | **629 passed** | Main CI, Python 3.11 unit-test job; CI also reports 629 tests collected |
| Statement coverage | **78.47%** | Main CI coverage report; gate is 77% |
| Prompt-injection regex patterns | **55** | `src/mcp_monitor/detectors/prompt_injection.py`, `INJECTION_PATTERNS` contains 55 compiled entries |
| Elastic Security rules | **9** | `detection_rules/elastic_rules.toml` contains 9 `[[rule]]` records |
| Core SIEM tests | **21** | `tests/test_siem.py` contains 21 `test_*` functions |
| Additional SIEM scenario-runner tests | **7** | `tests/test_siem_scenarios.py` contains 7 `test_*` functions |

## Claim boundary

These values describe the committed repository and the cited CI run. They are not claims of universal detection effectiveness. The gateway only governs calls that are routed through the enforcement path, and heuristic detectors can have false positives and false negatives.

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
