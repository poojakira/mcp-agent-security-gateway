# Resume Evidence

This file exists to make the quantitative claims used on Pooja Kiran's resume independently auditable without confusing a pinned resume snapshot with the repository's newer state.

## Resume snapshot

The resume uses this validated historical snapshot:

- **622 passing tests**
- **78% statement coverage**
- **9 MITRE ATT&CK-mapped Elastic Security detection rules**
- **21 core SIEM tests**

### 622 tests and 78% coverage

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

The resume rounds the measured 78.41% statement coverage to **78%**.

### 9 Elastic Security rules

`detection_rules/elastic_rules.toml` contains **9** `[[rule]]` records. These are ATT&CK-mapped Elastic Security detection rule definitions. They are the source behind the resume's "9" claim.

For precision, "9 Elastic Security detection rules" is the repository-native wording. These rules can generate alerts when their conditions match; the repository does not claim that exactly nine alert events occurred.

### 21 SIEM tests

`tests/test_siem.py` contains **21** `test_*` test functions covering ECS event formatting, correlation behavior, and shipping behavior.

## Current repository state

The repository has grown since the resume snapshot. Current verified evidence records **629 passing tests at 78.47% statement coverage**. That does not invalidate the resume's earlier **622 / 78%** snapshot; it means the test suite increased after that validated CI run.

The resume snapshot is intentionally frozen so applications already submitted remain traceable to a reproducible historical run.
