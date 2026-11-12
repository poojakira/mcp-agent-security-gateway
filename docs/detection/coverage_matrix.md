> **Evidence reconciliation (2026-11-11; living reference):** Historical results below retain their original dates and denominators. Latest tested Phase 1–16 development SHA is `43a72c8984bf9a472b9055d4f9e84cc759f61718` ([CI](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42971171992): 1,211 passed, 6 skipped per Python version), **not** a merged or production-approved release. Offline research tests require no paid provider or provider-issued API keys; deployed HTTP authentication and unverified real credential revocation remain separate. See [operating restrictions](../../PRODUCTION.md) and [release evidence](../../docs/review/PHASE1_16_RELEASE_CANDIDATE_NO_GO_20261110.md).

# Detection Coverage Matrix

> **Review context (2026-11-09):** Technique mappings mean rules have been mapped to a known taxonomy, not that every attack technique, environment, or variant has been effectively detected. The [integrated release-readiness gate](../../docs/review/PHASE13_RELEASE_READINESS.md) is **PRODUCTION NO-GO**.
> Coverage is measured against the set of ATT&CK techniques referenced by these rules. It does not imply coverage of the full ATT&CK matrix.

- Generated: `2026-09-28T06:21:46Z`
- Correlation rules: **6**
- Elastic rules: **9**
- Techniques referenced: **7** (T1005, T1059, T1074, T1190, T1199, T1567, T1595)

## Rule → MITRE ATT&CK / ATLAS mapping

| Source | Rule | Severity | Tactic | Technique | ATLAS cross-ref |
|---|---|---|---|---|---|
| correlation | `COR-001` | critical | TA0010 Exfiltration | T1567 Exfiltration Over Web Service | AML.T0024 (Exfiltration via ML Inference API) |
| correlation | `COR-002` | critical | TA0004 Privilege Escalation | T1059 Command and Scripting Interpreter | AML.T0051 (LLM Prompt Injection) |
| correlation | `COR-003` | critical | TA0010 Exfiltration | T1199 Trusted Relationship | — |
| correlation | `COR-004` | high | TA0001 Initial Access | T1190 Exploit Public-Facing Application | — |
| correlation | `COR-005` | critical | TA0010 Exfiltration | T1567 Exfiltration Over Web Service | AML.T0024 (Exfiltration via ML Inference API) |
| correlation | `COR-006` | high | TA0009 Collection | T1074 Data Staged | AML.T0035 (ML Artifact Collection) |
| elastic | `MCP Gateway: Prompt Injection Blocked` | critical | TA0002 Execution | T1059 Command and Scripting Interpreter | AML.T0051 (LLM Prompt Injection) |
| elastic | `MCP Gateway: Data Exfiltration Attempt` | high | TA0010 Exfiltration | T1567 Exfiltration Over Web Service | AML.T0024 (Exfiltration via ML Inference API) |
| elastic | `MCP Gateway: Shadow MCP Server Detected` | high | TA0001 Initial Access | T1199 Trusted Relationship | — |
| elastic | `MCP Gateway: PII Detected in Tool Arguments` | high | TA0009 Collection | T1005 Data from Local System | AML.T0035 (ML Artifact Collection) |
| elastic | `MCP Gateway: Circuit Breaker Opened` | medium | — | — | — |
| elastic | `MCP Gateway: Rate Limit Exceeded` | medium | — | — | — |
| elastic | `MCP Gateway: Process Spawn Attempt Blocked` | critical | TA0002 Execution | T1059 Command and Scripting Interpreter | AML.T0051 (LLM Prompt Injection) |
| elastic | `MCP Gateway: Multiple Blocks from Same Session (Probing)` | high | TA0043 Reconnaissance | T1595 Active Scanning | — |
| elastic | `MCP Gateway: Recon then Exfiltration (Attack Chain)` | critical | TA0010 Exfiltration | T1567 Exfiltration Over Web Service | AML.T0024 (Exfiltration via ML Inference API) |

## Coverage summary

- Every referenced ATT&CK technique is covered by at least one active rule.

### Operational rules without an ATT&CK mapping

These are availability/operational detections, not TTP detections:

- (elastic) `MCP Gateway: Circuit Breaker Opened`
- (elastic) `MCP Gateway: Rate Limit Exceeded`
