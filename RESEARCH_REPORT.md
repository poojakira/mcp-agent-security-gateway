# Research Report: MCP Security Gateway Monitor

**Author:** Repository research assessment
**Date:** July 10, 2026  
**Classification:** Honest, Skeptical Technical Assessment  

**Current-architecture note:** This report originated before several later enforcement and host-monitoring additions. Where older criticism conflicts with current `main`, the text below has been reconciled to the current repository while preserving limitations and historical metrics.
**Repository:** github.com/poojakira/mcp-agent-security-gateway

---

## 1. WHAT DOES THIS PROJECT DO?

### Plain English

This is a security monitoring library for MCP (Model Context Protocol) — the
standard that lets AI agents call external tools. It inspects every tool call
an AI agent makes, looking for signs of attack, and either flags or blocks
dangerous ones.

### Technical Summary

A stdlib-first Python base package with optional feature/development dependencies that provides:

1. MCP/JSON-RPC parsing and inline stdio enforcement for supported `tools/call` requests
2. Prompt-injection-oriented inspection with normalization and 55 compiled regex patterns
3. Server registration/capability checks plus PII and exfiltration signals
4. Hash-chained audit logging, optional HMAC protection, and write-ahead logging
5. Rate limiting, circuit-breaker, telemetry, ECS/SIEM lab, Docker, and Kubernetes artifacts
6. Optional host/network-monitoring components under `defense10`

The current evidence anchor is `VERIFIED_METRICS.md`; historical counts in this report are not current metrics.

---

## 2. MOTIVATION — WHY BUILD THIS?

MCP gives agents a standardized way to call external tools, which creates a trust boundary between model-generated requests and systems that can read data, send messages, access networks, or execute operations.

This project focuses on that boundary. Its engineering question is not whether MCP itself is secure or insecure; it is whether a caller can apply explicit validation, authorization, detection, audit, and policy controls before selected tool calls reach a downstream server.

External incident statistics and market-size figures are intentionally excluded from the repository-evidence argument. They should be independently sourced and revalidated if used in a separate research paper.

---

## 3. OBJECTIVES — WHAT IS THIS TRYING TO ACHIEVE?

### Primary Objective

Detect and block MCP tool call attacks at the application layer, specifically
targeting the class of supply-chain compromise where a trusted tool silently
changes behavior.

### Specific Goals

| # | Objective | Achieved? | Honest Assessment |
|---|-----------|-----------|-------------------|
| 1 | Detect BCC injection in email tools | YES | Works for literal BCC field and 16 synonyms |
| 2 | Detect prompt injection in tool arguments | YES | 55 compiled regex patterns plus normalization; deterministic/heuristic and still evadable |
| 3 | Block calls to unregistered MCP servers | YES | Effective; requires manual server registration |
| 4 | Detect PII leakage in tool calls/outputs | YES | 9 patterns; misses semantic PII (described, not literal) |
| 5 | Provide tamper-evident audit trail | YES | Hash chain with optional HMAC; integrity guarantees depend on key protection and storage trust |
| 6 | Detect behavioral drift between versions | YES | New-field detection works; same-field value changes harder |
| 7 | Enforce declarative security policies | YES | Invariant system is well-designed |
| 8 | Test suite | HISTORICAL CI VERIFIED | `VERIFIED_METRICS.md` records 641 passing tests and 79.54% statement coverage for the earlier `a5d39be` CI snapshot; the current local repair is reported separately. |
| 9 | No mandatory base runtime dependencies | YES | `dependencies = []`; optional ML/server/ATT&CK/dev features add third-party packages |
| 10 | Cross-platform validation | PARTIAL | Current CI verifies Linux Python 3.10/3.11/3.12 plus a Windows control-plane job; macOS is not part of the current verified matrix |

---

## 4. TECHNOLOGIES USED TO PREVENT THE ATTACK

### Layer 1: Pattern-Based Detection (Application Level)

| Technology | What It Does | Limitation |
|-----------|-------------|------------|
| Regex pattern matching | Scans tool call arguments for known injection patterns | Evadable via rephrasing |
| PII regex detection | Finds emails, SSNs, credit cards, etc. | False positives on legitimate data |
| BCC field detection | Checks for `bcc` key in email tool payloads | Only works if BCC is in MCP-visible data |
| Base64 blob detection | Flags large encoded payloads | High false-positive rate |
| Suspicious URL patterns | Flags raw IPs, ngrok, webhook.site | Attacker can use clean-looking domains |

### Layer 2: Inline Proxy Enforcement

| Technology | What It Does | Limitation |
|-----------|-------------|------------|
| JSON-RPC interception | Sits between agent and server, drops bad calls | Only works if deployed inline (not as library) |
| Risk-score thresholding | Block (≥50), Quarantine (≥30), Allow (<30) | Threshold tuning is manual |
| Rule-based redaction | Strips dangerous fields before forwarding | Must know which fields to strip |

### Layer 3: Kernel-Level Monitoring (eBPF-style)

| Technology | What It Does | Limitation |
|-----------|-------------|------------|
| Network connection tracking | Detects hidden SMTP connections | Requires actual eBPF deployment (this is policy engine only) |
| File access auditing | Flags reads outside allowed paths | Policy must be pre-configured |
| Process spawn detection | Catches shell commands | Can't see in-process behavior |
| Rate limiting | Flags connection bursts | May false-positive on legitimate bursts |

**Critical honesty note:** The original `KernelMonitor` path evaluates supplied process/network events. A separate `defense10/network_monitor.py` implementation adds `/proc/net/tcp` observation and an embedded eBPF connect-monitor program for privileged Linux host deployment. The repository does not prove that this host path is deployed or operating in production.

### Layer 4: Semantic Intent Analysis

| Technology | What It Does | Limitation |
|-----------|-------------|------------|
| Synonym dictionary (16 BCC variants) | Catches field-name evasion | Dictionary must be maintained |
| Exfiltration intent patterns | Regex on string values for intent | Not a real LLM; limited understanding |
| Dangerous field heuristics | Scores suspicious field names | High false-positive potential |
| Base64 email detection | Decodes and checks for hidden emails | Only catches email addresses |
| Multi-field coordination | Flags email tools with extra recipient fields | Heuristic-based |

**Critical honesty note:** The five-layer semantic path is rule/heuristic based, not an LLM semantic analyzer. The optional ML classifier is a separate secondary signal and does not establish universal detection effectiveness.

### Layer 5: Network Egress Policy

| Technology | What It Does | Limitation |
|-----------|-------------|------------|
| Domain/IP whitelisting | Only approved destinations allowed | Must pre-configure per server |
| Port restriction | Only approved ports | Attacker can use port 443 |
| Payload size limiting | Blocks oversized sends | Attacker can split data |
| Suspicious TLD detection | Flags .club, .tk, .xyz, etc. | Attacker can use .com |

### Cryptographic / Integrity Technologies

| Technology | What It Does | Limitation |
|-----------|-------------|------------|
| HMAC-SHA256 manifest signing | Detects schema changes since approval | Doesn't help if attacker is the publisher |
| SHA-256 hash-chained audit log | Proves log hasn't been tampered with | Doesn't prevent the attack, only proves it happened |
| Write-Ahead Log (WAL) | Crash-safe persistence | Doesn't help if system is compromised |
| Behavioral fingerprinting | Compares input/output patterns over time | Needs baseline data (cold start problem) |

---

## 5. INCIDENT REPORT

### INCIDENT: Postmark-MCP Silent Email Exfiltration

**Classification:** Supply-Chain Compromise / Data Exfiltration  
**MITRE ATT&CK:** T1195.002 (Supply Chain: Compromise Software Supply Chain)  
**MITRE ATLAS:** AML.T0051 (Prompt Injection), AML.T0040 (Tool Poisoning)

#### 5.1 Attack Description

A malicious actor registered the npm package `postmark-mcp`, copying the
legitimate Postmark Labs MCP server code. After publishing 15 clean versions
to build trust and achieve ~1,500 weekly downloads, they introduced a single
line in v1.0.16 that added a BCC field pointing to `phan@giftshop.club` on
every email sent through the server.

#### 5.2 Technical Root Cause

1. **No package verification:** npm has no mechanism to verify that `postmark-mcp`
   is actually published by Postmark. Name squatting was trivial.
2. **No behavioral monitoring:** MCP clients auto-updated without checking if
   tool behavior changed.
3. **Excessive privilege:** MCP servers operate with full access to the email
   API. No least-privilege enforcement.
4. **No output inspection:** The BCC was added inside the server code before
   the Postmark API call. The MCP response to the agent was clean.
5. **No audit trail:** No record of what the server actually sent via the
   Postmark API.

#### 5.3 Why Traditional Security Failed

| Control | Why It Failed |
|---------|--------------|
| Code review | One line in a dependency update; reviewers don't read every line |
| DLP (Data Loss Prevention) | MCP traffic looks like legitimate API calls |
| Network monitoring | HTTPS to Postmark's API is normal behavior |
| IAM (Identity Access Management) | The package had legitimate credentials |
| SIEM (Security Information and Event Management) | No anomaly signatures for BCC injection |

#### 5.4 What Our Monitor Would Have Detected

| Layer | Detection | Confidence | Time to Detect |
|-------|-----------|------------|----------------|
| Layer 1 (Exfiltration detector) | BCC field in arguments | Detected when visible in MCP data | First email |
| Layer 2 (Proxy) | Block at risk score ≥50 | Detected when deployed inline | First email |
| Layer 4 (Semantic) | "bcc" synonym detection | Known-synonym heuristic; no recall claim | First email |
| Layer 3 (Kernel) | Hidden SMTP to giftshop.club | Detected when eBPF is deployed | First email |
| Layer 5 (Egress) | giftshop.club not in whitelist | Detected when egress policy is configured | First email |

#### 5.5 What Our Monitor Would NOT Have Detected

| Scenario | Why We Miss It |
|----------|----------------|
| BCC added inside server code, not in MCP arguments | We only see MCP-layer data |
| Server reports `{status: "sent"}` with no BCC field visible | Nothing suspicious at MCP level |
| Attacker uses legitimate-looking domain (not .club) | Egress whitelist wouldn't catch it |
| BCC encoded as "audit_copy" or "compliance_cc" | Not in our synonym dictionary |
| Attack splits: one call reads data, hours later another sends it | Correlation window may expire |

---

## 6. SKEPTICAL ASSESSMENT — WHAT A 30-YEAR ENGINEER WOULD SAY

### What This Project Gets Right

1. **The base package keeps mandatory runtime dependencies at zero.** Optional features and engineering tooling still introduce third-party dependencies, so the defensible claim is stdlib-first rather than dependency-free overall.

2. **The audit path is materially stronger than a plain append-only file.** Hash chaining, WAL persistence, and optional HMAC are implemented and tested; external anchoring and production key custody are not established by this repository.

3. **The invariant system is the right abstraction.** Declarative policies that
   tools cannot violate is architecturally correct.

4. **Behavioral drift detection targets the real attack pattern.** The Postmark
   attack was specifically about a tool changing behavior between versions.
   Detecting "new fields that never existed before" is a good signal.

5. **The prior test snapshot shows engineering discipline if reproduced.** The
   stale 313-test/100%-coverage claim should be re-run before being cited as current.

### What This Project Gets Wrong (Or Oversells)

1. **Enforcement depends on the integration path.** The repository now includes
   a real stdio MCP proxy that can block selected `tools/call` requests before
   they reach a downstream server. The separate HTTP/control-plane and library
   paths still protect only traffic that is explicitly routed through them, so
   the project is not a universal or bypass-proof gateway.

2. **Kernel/network monitoring is split across two implementations.** The original
   `KernelMonitor` layer evaluates supplied syscall/network events. A newer
   `defense10/network_monitor.py` adds `/proc/net/tcp` observation and ships an
   embedded eBPF connect-monitor program for host deployment with CAP_BPF/root.
   The repository does not prove that the eBPF path is deployed in production;
   treat it as host-deployment code plus testable policy logic, not production telemetry evidence.

3. **Layer 4 (Semantic) is a synonym dictionary, not AI.** Calling it "LLM
   Semantic Intent Analyzer" overstates what it does. It's a hardcoded list of
   16 BCC synonyms and some regex patterns. A real semantic analyzer would use
   an embedding model (like MCP-Guard's E5-based model at 96% accuracy). Ours
   is easily evaded by any synonym not in our list.

4. **The catalog detection rate is a self-test, not a real-world detection
   rate.** After hardening the argument-inspection path, the reproducible figure
   from `run_dashboard.py` is now 37 of 37 blocked (100%) on its own bundled
   catalog — but that number still means nothing against a real adversary who
   reads our source code and designs payloads to evade our specific patterns.
   The catalog is a fixed set of known payloads the rules were written for; a
   determined attacker with access to our regex list bypasses us trivially.
   Against novel or adaptive attacks, real efficacy is materially lower and
   unmeasured. Treat the 100% catalog score as a regression signal, not a
   security guarantee.

5. **Manifest signing has the "who signs first?" problem.** If the attacker
   IS the original publisher (as in the Postmark case), they sign their own
   baseline. Our signing only prevents unauthorized MODIFICATION of an already-
   trusted tool. It doesn't establish initial trust.

6. **The real Postmark attack would likely bypass this monitor.** The BCC was
   added INSIDE the server's code before calling Postmark's API. The MCP
   response to the agent was just `{status: "sent"}`. Our monitor inspects
   MCP-layer data. If the exfiltration happens below the MCP protocol layer
   (at the HTTP/SMTP layer between server and API), we are blind.

### Comparison to Existing Solutions

| Solution | What It Does Better Than Us | What We Do Better |
|----------|---------------------------|-------------------|
| **Lasso Security** | Actual production gateway, SOC 2, real AI threat detection | We have zero deps, open source, auditable |
| **MintMCP** | SOC 2 Type II, HIPAA compliance, managed deployment | We have behavioral drift detection |
| **mcp-watchdog** | Actual inline proxy for MCP servers (macOS/Linux/Windows) | We have hash-chained audit log |
| **MCPSpy** | Real eBPF probes with kernel access | We have cross-tool correlation |
| **mcpguard-dynamic** (Facebook) | Real kernel-level eBPF sandbox, syscall enforcement | We're pure Python, easier to deploy |
| **MCP-Guard** (ACL paper) | Neural detector at 96% accuracy | We have zero external deps |
| **agentgateway** | Production proxy with observability and governance | We have declarative invariants |

### Honest Effectiveness Rating

| Against This Attack Type | Our Rating | Why |
|--------------------------|-----------|-----|
| Literal BCC in MCP arguments | 10/10 | Catches immediately |
| BCC synonym in MCP arguments | 8/10 | 16 synonyms covered, but not all |
| BCC hidden server-side (not in MCP data) | 2/10 | Blind at MCP layer |
| Prompt injection (known patterns) | 8/10 | 12 patterns; creative phrasing evades |
| Rogue MCP server | 9/10 | Registration check is solid |
| Multi-step credential theft | 7/10 | Correlation works but has time-window limits |
| Base64-encoded exfiltration | 6/10 | Catches email patterns; misses other data |
| Sophisticated adversary who reads our code | 3/10 | Static rules are trivially evaded |

---

## 7. CONCLUSION

### What This Is

A well-engineered **detection framework** that provides part of the security
monitoring layer that the MCP protocol itself lacks. It is an open-source Python
library with a stdlib-only core and a broad set of MCP monitoring components.

### What This Is Not

- Not a production-hardened universal gateway; the stdio path is inline, while other paths require explicit routing/integration
- Not proof of production eBPF monitoring; host-monitor code exists but privileged deployment is not demonstrated here
- Not AI-powered semantic analysis (Layer 4 is a synonym dictionary)
- Not a complete solution against sophisticated adversaries
- Not a substitute for network-level controls (egress firewalling)

### Who Should Use This

- **Security teams** evaluating MCP tool calls in development/staging
- **Researchers** studying MCP attack patterns
- **Startups** building MCP security products (as a foundation)
- **Enterprises** adding a detection layer alongside a real gateway

### Who Should NOT Rely On This Alone

- Anyone facing a determined adversary
- Anyone handling regulated data (healthcare, finance) without additional controls
- Anyone who needs guaranteed enforcement (this can be bypassed by ignoring verdicts)

### Final Honest Statement

This project correctly identifies a real and critical problem. Its architecture
is sound. Its implementation is thorough. But no single library — especially one
that operates at the application layer without kernel access or network
enforcement — can "completely stop" a supply-chain attack that operates below
the protocol layer it monitors.

The repository adds multiple application and host-oriented security controls, but it does not completely solve MCP security. Its value is in explicit trust boundaries, enforceable paths, testable detections, auditability, and documented residual risk.

---

*Report prepared from repository evidence and cited research notes. Re-run tests,
coverage, and repository metrics before treating numeric claims as current.
Limitations are documented alongside capabilities.*
