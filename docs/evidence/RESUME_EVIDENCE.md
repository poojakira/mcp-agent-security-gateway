> **Evidence reconciliation (2026-11-11; living reference):** Historical results below retain their original dates and denominators. Latest tested Phase 1–16 development SHA is `43a72c8984bf9a472b9055d4f9e84cc759f61718` ([CI](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42971171992): 1,211 passed, 6 skipped per Python version), **not** a merged or production-approved release. Offline research tests require no paid provider or provider-issued API keys; deployed HTTP authentication and unverified real credential revocation remain separate. See [operating restrictions](../../PRODUCTION.md) and [release evidence](../../docs/review/PHASE1_16_RELEASE_CANDIDATE_NO_GO_20261110.md).

# Resume Evidence

> **Review context (2026-11-09):** Claims about test counts, coverage and signature inventories apply only to the indicated October commits. The phases 1–16 candidate has different scope and a separate release gate. The [integrated release-readiness gate](../../docs/review/PHASE13_RELEASE_READINESS.md) is **PRODUCTION NO-GO**.
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

The current evidence anchor is [../../VERIFIED_METRICS.md](../../VERIFIED_METRICS.md).

Latest cited CI code snapshot: `c75c52db` (CI run `38462601803`, October 13, 2026).

- **782 passing tests**
- **81.93% statement coverage** (5,657 statements, 1,022 missed)
- **69 prompt-injection patterns**
- **9 Elastic Security rules**
- **21 core SIEM tests**
- Stable multi-credential authentication plus trusted-proxy-aware source attribution
- Local HMAC-SHA256 credential/network fingerprinting without raw credential/IP export
