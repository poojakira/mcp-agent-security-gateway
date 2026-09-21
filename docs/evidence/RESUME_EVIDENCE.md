# Resume Evidence

This file preserves the quantitative snapshot used in previously submitted application material without confusing it with the repository's newer state.

## Frozen application snapshot

- **622 passing tests**
- **78% statement coverage**
- **9 MITRE ATT&CK-mapped Elastic Security detection rules**
- **21 core SIEM tests**

### CI proof

GitHub Actions run: https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/33696855146  
Head commit: `cb604fd1b812fcf28eb010c65be7bccc307aaf5d`  
Python 3.11 job: `100467629575`

The successful CI log reports:

```text
TOTAL 4679 1010 78%
Required test coverage of 77% reached. Total coverage: 78.41%
622 passed in 62.40s
Collected 622 tests
```

The resume rounds 78.41% to **78%**.

### Detection-rule proof

`detection_rules/elastic_rules.toml` contains **9** `[[rule]]` records.

### SIEM-test proof

`tests/test_siem.py` contains **21** `test_*` functions covering ECS formatting, correlation behavior, and shipping behavior.

## Current repository state

The current evidence anchor is [../../VERIFIED_METRICS.md](../../VERIFIED_METRICS.md). The repository has grown since the frozen application snapshot; current metrics must not be substituted into older submitted material retroactively.
