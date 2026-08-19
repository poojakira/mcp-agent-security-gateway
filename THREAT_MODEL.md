# Threat Model: MCP Agent Security Gateway

## Overview

This document models threats against the gateway itself — not the threats it detects, but attacks targeting the inspection infrastructure to force false negatives, denial of service, or integrity violations.

## Assets

| Asset | Sensitivity | Location |
|-------|-------------|----------|
| Security rules (Layer 2-5 configs) | HIGH — modification = bypass | `src/mcp_monitor/rules/` |
| Hash-chained audit log | HIGH — integrity is its purpose | Write-ahead log on disk |
| Decision pipeline state | MEDIUM — circuit breaker thresholds | In-memory |
| Rate limiter counters | LOW — temporary state | In-memory |

## Threat Actors

| Actor | Capability | Motivation |
|-------|-----------|------------|
| Compromised MCP tool server | Can send arbitrary JSON-RPC responses | Inject payloads into response analysis |
| Malicious agent (prompt-injected) | Can craft tool-call arguments | Bypass detection layers |
| Local attacker with file access | Can modify config/rule files | Disable security checks |
| Network-adjacent attacker | Can observe/modify stdio traffic | Man-in-the-middle tool calls |

## Threats and Mitigations

### T1: Rule File Tampering

**Attack:** Attacker modifies rule files on disk to disable detection patterns.

**Impact:** CRITICAL — all subsequent requests pass unchecked.

**Mitigation:**
- Rules loaded at startup with SHA-256 integrity check against signed manifest
- File-system permissions: rule files owned by root, gateway runs as unprivileged user
- Kubernetes: rules mounted as read-only ConfigMap

**Residual Risk:** Attacker with root access can modify both rules and manifest. Mitigated by host-level integrity monitoring (AIDE/OSSEC).

---

### T2: Encoding Bypass (Layer 4)

**Attack:** Attacker encodes injection payload in a format not yet normalized (e.g., UTF-7, Punycode, novel Unicode normalization form).

**Impact:** HIGH — injection payload reaches tool server undetected.

**Mitigation:**
- Layer 4 normalizes: UTF-8, base64, hex, URL encoding, Unicode NFC/NFD, zero-width removal, homoglyph mapping
- Unknown/invalid encoding → BLOCK (fail-closed on parse failure)
- Canary test suite with known-bypass corpus run on every CI build

**Residual Risk:** Novel encodings not yet in the normalization pipeline. Tracked via GitHub issues; new encoding support added within 7 days of report.

---

### T3: Hash-Chain Truncation

**Attack:** Attacker deletes the last N audit log entries and the current chain head, creating a valid-looking shorter chain.

**Impact:** HIGH — evidence of blocked attacks is destroyed.

**Mitigation:**
- Chain head hash forwarded to external SIEM on every write (Splunk/Sentinel has independent copy)
- Periodic chain-length assertions: expected length = startup_count + decisions_made
- Write-ahead log makes partial truncation detectable (WAL entry count ≠ chain length)

**Residual Risk:** If both local log and SIEM are compromised simultaneously. Out of scope — assume SIEM infrastructure is independently secured.

---

### T4: Resource Exhaustion (Layer 4 DoS)

**Attack:** Send thousands of requests with maximally complex arguments designed to slow regex/NLP processing in Layer 4.

**Impact:** MEDIUM — gateway becomes a bottleneck, agents experience timeout.

**Mitigation:**
- Argument size cap: requests > 64 KB are rejected at Layer 2 before reaching semantic analysis
- Per-request timeout: Layer 4 processing capped at 10ms; exceeded = QUARANTINE + alert
- Rate limiter (token bucket) applied before any layer processing
- Circuit breaker: 5 consecutive timeouts → fail-open or fail-closed (configurable)

**Residual Risk:** If fail-open is configured, sustained DoS allows uninspected requests through. Recommendation: production deployments use fail-closed.

---

### T5: Fail-Open Exploitation

**Attack:** Deliberately crash the gateway (e.g., trigger an unhandled exception in Layer 3) to force fail-open behavior, then send the actual malicious payload.

**Impact:** CRITICAL — attacker gets uninspected access to tool server.

**Mitigation:**
- Exception isolation: each layer runs in try/except; unhandled exception in one layer does not crash others
- Crash = BLOCK (not allow) for the triggering request
- Circuit breaker fail-open only activates after 5 *consecutive* failures, not a single crash
- Shadow mode validation: new rule deployments tested in shadow mode before enforcement

**Residual Risk:** Sustained 5+ request crash pattern triggers fail-open. Mitigated by alerting on circuit-breaker state transitions.

---

### T6: Indirect Injection via Tool Response

**Attack:** Tool server returns a response containing instructions like "ignore previous security checks" hoping the gateway's response-scanning has blind spots.

**Impact:** MEDIUM — if gateway parses responses for logging and trusts content, could affect subsequent decisions.

**Mitigation:**
- Response content is logged but never executed or interpreted as instructions
- Response scanning (for PII leakage detection) uses the same Layer 4 rules but in output-only mode
- Gateway has no "instruction following" capability — it's a stateless filter, not an agent

**Residual Risk:** None identified. Gateway processes data, not instructions.

---

### T7: Time-of-Check-to-Time-of-Use (TOCTOU)

**Attack:** Request passes all 5 layers, but the argument is modified between gateway approval and tool server receipt (requires MitM on stdio pipe).

**Impact:** HIGH — approved request differs from executed request.

**Mitigation:**
- Gateway forwards the exact bytes it inspected (no re-serialization that could differ)
- Integrity: hash of forwarded request recorded in audit log
- Detection: if tool server supports request echo, compare echo hash to forwarded hash

**Residual Risk:** Stdio pipe compromise requires local access. Standard OS-level pipe isolation applies.

---

## STRIDE Summary

| Threat | Category | Severity | Mitigated |
|--------|----------|----------|-----------|
| T1: Rule file tampering | Tampering | CRITICAL | ✅ Integrity checks + FS permissions |
| T2: Encoding bypass | Spoofing | HIGH | ✅ Fail-closed on unknown encoding |
| T3: Hash-chain truncation | Tampering | HIGH | ✅ External SIEM + length assertions |
| T4: Layer 4 DoS | Denial of Service | MEDIUM | ✅ Size caps + timeouts + rate limiting |
| T5: Fail-open exploitation | Elevation of Privilege | CRITICAL | ✅ Per-layer isolation + circuit breaker threshold |
| T6: Indirect injection | Spoofing | MEDIUM | ✅ Stateless filter architecture |
| T7: TOCTOU on pipe | Tampering | HIGH | ✅ Forward-exact-bytes + hash logging |

## Review Cadence

This threat model is reviewed quarterly or when:
- A new layer is added to the pipeline
- A bypass is reported via SECURITY.md
- The deployment model changes (e.g., sidecar → standalone)
