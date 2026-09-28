# Detection Coverage Matrix

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
