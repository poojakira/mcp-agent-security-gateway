# Incident Runbook — mcp-agent-security-gateway

> Production incident response procedures for teams operating the MCP Agent Security Gateway.

---

## Table of Contents

1. [Severity Levels](#severity-levels)
2. [Escalation Matrix](#escalation-matrix)
3. [Initial Response Checklist](#initial-response-checklist)
4. [Common Failure Modes & Mitigations](#common-failure-modes--mitigations)
5. [Rollback Procedures](#rollback-procedures)
6. [Communication Templates](#communication-templates)
7. [Post-Incident Review Template](#post-incident-review-template)

---

## Severity Levels

| Level | Definition | Response Time | Update Cadence | Examples |
|-------|-----------|---------------|----------------|----------|
| **SEV1** | Complete gateway failure; all MCP calls blocked or bypassing security | **15 minutes** | Every 30 min | Gateway crash loop, policy engine unresponsive, full bypass detected |
| **SEV2** | Partial degradation; some security layers non-functional | **30 minutes** | Every 1 hour | Single defense layer failing, elevated false-positive rate >10%, intermittent drops |
| **SEV3** | Minor impact; non-critical functionality affected | **2 hours** | Every 4 hours | Logging pipeline delayed, metrics gaps, non-blocking validation warnings |
| **SEV4** | Cosmetic or low-impact issue; no security degradation | **24 hours** | Daily | Dashboard rendering issues, documentation errors, non-critical deprecation warnings |

### Severity Determination Flowchart

```
Is the gateway fully down or bypassed?
  YES → SEV1
  NO  → Are security policies being enforced correctly?
          NO  → SEV2
          YES → Is there user-visible degradation?
                  YES → SEV3
                  NO  → SEV4
```

---

## Escalation Matrix

| Severity | Primary Responder | Escalation (if no progress in SLA) | Executive Notification |
|----------|-------------------|-------------------------------------|------------------------|
| **SEV1** | On-call security engineer | Engineering manager + Security lead (15 min) | VP Engineering (30 min) |
| **SEV2** | On-call engineer | Security lead (1 hour) | Engineering manager (2 hours) |
| **SEV3** | Assigned engineer (next business day OK) | Team lead (4 hours) | — |
| **SEV4** | Backlog triage | — | — |

### On-Call Contacts

| Role | Primary Channel | Backup Channel |
|------|----------------|----------------|
| On-call engineer | PagerDuty | #incident-response Slack |
| Security lead | PagerDuty | Phone (see internal directory) |
| Engineering manager | Slack DM | Phone |

### Escalation Rules

1. **No acknowledgment within response time** → auto-escalate to next tier
2. **No resolution progress within 2× response time** → escalate severity by one level
3. **Customer-reported SEV1** → immediate bridge call, all hands

---

## Initial Response Checklist

When an incident is detected:

- [ ] **Acknowledge** the alert in PagerDuty / monitoring system
- [ ] **Assess severity** using the determination flowchart above
- [ ] **Open incident channel** — `#inc-YYYYMMDD-brief-description`
- [ ] **Declare incident commander** (first responder until handed off)
- [ ] **Check gateway health**:
  ```bash
  # Health check endpoint
  curl -s http://gateway:8080/health | jq .

  # Check all 5 defense layers
  curl -s http://gateway:8080/health/layers | jq .

  # Recent error rate
  curl -s http://gateway:8080/metrics | grep error_rate
  ```
- [ ] **Check logs** for immediate root cause:
  ```bash
  # Last 100 error-level logs
  journalctl -u mcp-gateway --since "5 min ago" -p err

  # Or containerized:
  kubectl logs -l app=mcp-gateway --tail=100 --since=5m | grep -i error
  ```
- [ ] **Determine blast radius** — which agents/consumers are affected?
- [ ] **Begin mitigation** (see failure modes below)
- [ ] **Communicate** — post initial status update

---

## Common Failure Modes & Mitigations

### 1. Gateway Process Crash / OOM

**Symptoms:** Health check returns 503, process restarts visible, OOM-kill in system logs.

**Immediate Mitigation:**
```bash
# Check memory usage
kubectl top pods -l app=mcp-gateway

# Force restart with increased memory
kubectl rollout restart deployment/mcp-gateway

# If OOM, scale vertically temporarily
kubectl set resources deployment/mcp-gateway -c gateway --limits=memory=2Gi
```

**Root Cause Investigation:**
- Check for memory leaks in recent deployments
- Review payload sizes — are agents sending unexpectedly large calls?
- Check for circular policy evaluation

---

### 2. Policy Engine Deadlock / Timeout

**Symptoms:** Requests hanging, p99 latency spike, policy evaluation timeouts in logs.

**Immediate Mitigation:**
```bash
# Enable fail-open temporarily (ONLY for availability-critical scenarios)
# WARNING: This reduces security posture
export MCP_GATEWAY_POLICY_TIMEOUT_ACTION=allow
kubectl rollout restart deployment/mcp-gateway

# Or increase timeout
export MCP_GATEWAY_POLICY_TIMEOUT_MS=10000
```

**Root Cause Investigation:**
- Check for recursive policy rules
- Verify policy file hasn't grown excessively
- Check if external policy data sources are slow

---

### 3. False Positive Surge (Legitimate Calls Blocked)

**Symptoms:** Agents reporting failures, block rate spike >10% above baseline, user complaints.

**Immediate Mitigation:**
```bash
# Identify which rule is triggering
grep "BLOCKED" /var/log/mcp-gateway/audit.log | tail -50 | \
  jq -r '.rule_id' | sort | uniq -c | sort -rn

# Temporarily disable overly aggressive rule
mcp-gateway rules disable RULE_ID --duration 1h --reason "false-positive investigation"

# Or switch to audit-only mode for that layer
mcp-gateway layer set INPUT_VALIDATION --mode audit
```

**Root Cause Investigation:**
- Was a new rule deployed? Check recent policy changes
- Did agent behavior change? New tool calls or argument patterns?
- Is there a signature/pattern update that's too broad?

---

### 4. Security Bypass Detected

**Symptoms:** Audit logs show calls that should have been blocked passing through, integrity check failures.

**Immediate Mitigation:**
```bash
# CRITICAL: Enable strict mode immediately
mcp-gateway mode set STRICT --all-layers

# Block the specific bypass vector if known
mcp-gateway rules add EMERGENCY_BLOCK --pattern "<detected pattern>" --action deny

# Rotate any potentially compromised credentials
mcp-gateway credentials rotate --all

# Capture forensic snapshot
mcp-gateway forensic snapshot --output /tmp/incident-$(date +%s).tar.gz
```

**Root Cause Investigation:**
- Check if all 5 defense layers are active
- Review the specific call that bypassed — which layer(s) failed?
- Check for version skew between gateway and policy definitions
- Review recent configuration changes

---

### 5. Configuration Drift / Invalid Config

**Symptoms:** Gateway starts but some rules inactive, config validation warnings, inconsistent behavior across replicas.

**Immediate Mitigation:**
```bash
# Validate current config
mcp-gateway config validate

# Force reload from known-good source
mcp-gateway config reload --source git://main

# Check for config differences across replicas
for pod in $(kubectl get pods -l app=mcp-gateway -o name); do
  kubectl exec $pod -- mcp-gateway config hash
done
```

---

### 6. Upstream Dependency Failure

**Symptoms:** Gateway healthy but cannot reach logging/metrics backends, audit trail gaps.

**Immediate Mitigation:**
```bash
# Gateway should continue operating (zero runtime deps)
# Verify local buffering is active
mcp-gateway buffer status

# Check buffer isn't filling up
du -sh /var/lib/mcp-gateway/buffer/

# If buffer is full, flush to alternate sink
mcp-gateway buffer flush --target file:///tmp/emergency-audit.jsonl
```

---

## Rollback Procedures

### Application Rollback

```bash
# 1. Identify last known-good version
kubectl rollout history deployment/mcp-gateway

# 2. Rollback to previous revision
kubectl rollout undo deployment/mcp-gateway

# 3. Or rollback to specific revision
kubectl rollout undo deployment/mcp-gateway --to-revision=<N>

# 4. Verify rollback
kubectl rollout status deployment/mcp-gateway
curl -s http://gateway:8080/health | jq .version
```

### Configuration Rollback

```bash
# 1. List config history
mcp-gateway config history --limit 10

# 2. Restore specific version
mcp-gateway config restore --version <COMMIT_SHA>

# 3. Validate restored config
mcp-gateway config validate

# 4. Apply (hot-reload, no restart needed)
mcp-gateway config apply
```

### Policy Rollback

```bash
# 1. List policy versions
mcp-gateway policy versions

# 2. Rollback to specific policy version
mcp-gateway policy rollback --to <VERSION>

# 3. Verify all 5 layers are active
mcp-gateway layer status --all
```

### Emergency: Full System Rollback

For catastrophic failures affecting the entire deployment:

```bash
# 1. Switch traffic to standby (if available)
kubectl patch service mcp-gateway -p '{"spec":{"selector":{"version":"standby"}}}'

# 2. Rollback deployment, config, and policies atomically
./scripts/emergency-rollback.sh --confirm

# 3. Verify
./scripts/smoke-test.sh --environment production
```

### Rollback Decision Matrix

| Scenario | Rollback Target | Estimated Recovery |
|----------|-----------------|-------------------|
| Bad code deploy | Application version | 2–5 minutes |
| Bad policy rule | Policy version | < 1 minute (hot-reload) |
| Bad configuration | Config version | < 1 minute (hot-reload) |
| Infrastructure issue | Scale or failover | 5–10 minutes |
| Data corruption | Full restore from backup | 30–60 minutes |

---

## Communication Templates

### Initial Incident Notification

```
🚨 INCIDENT DECLARED — [SEV level]

Summary: [Brief description]
Impact: [Who/what is affected]
Status: Investigating
Commander: [Name]
Channel: #inc-YYYYMMDD-description
Next update: [Time]
```

### Status Update

```
📋 INCIDENT UPDATE — [SEV level] — [Status: Investigating/Mitigating/Monitoring]

Summary: [Brief description]
Impact: [Current impact]
Actions taken: [What has been done]
Current theory: [What we think is happening]
Next steps: [What we're doing next]
Next update: [Time]
```

### Resolution Notification

```
✅ INCIDENT RESOLVED — [SEV level]

Summary: [Brief description]
Duration: [Start time — End time]
Root cause: [Brief root cause]
Resolution: [What fixed it]
Follow-ups: [Tickets/actions created]
Post-incident review: [Scheduled date/time]
```

---

## Post-Incident Review Template

Complete within **3 business days** of SEV1/SEV2 resolution, **5 business days** for SEV3.

---

### Incident Post-Mortem: [Title]

**Date:** YYYY-MM-DD
**Severity:** SEV[1-4]
**Duration:** [Total time from detection to resolution]
**Authors:** [Names of review participants]
**Status:** [Draft / Final]

---

#### 1. Summary

_One paragraph describing what happened, the impact, and how it was resolved._

---

#### 2. Timeline (all times in UTC)

| Time | Event |
|------|-------|
| HH:MM | First alert fired / Issue detected |
| HH:MM | Incident declared, commander assigned |
| HH:MM | Root cause identified |
| HH:MM | Mitigation applied |
| HH:MM | Full resolution confirmed |
| HH:MM | Incident closed |

---

#### 3. Impact

- **Users/Agents affected:** [Number or scope]
- **Calls blocked incorrectly:** [Count, if applicable]
- **Calls passed incorrectly (bypass):** [Count — CRITICAL for security incidents]
- **Duration of degraded state:** [Time]
- **Data loss:** [Yes/No — describe if yes]
- **SLA impact:** [Any SLA breach?]

---

#### 4. Root Cause

_Detailed technical explanation of why the incident occurred. Include the chain of events._

---

#### 5. Detection

- How was this detected? (Alert / Customer report / Manual observation)
- Time to detection: [Duration from start of issue to first alert]
- Could we have detected this sooner? How?

---

#### 6. Resolution

_What actions resolved the incident? Include commands run, configs changed, etc._

---

#### 7. What Went Well

- [Bullet points of things that worked]

---

#### 8. What Went Poorly

- [Bullet points of things that didn't work or were slow]

---

#### 9. Action Items

| Action | Owner | Priority | Due Date | Ticket |
|--------|-------|----------|----------|--------|
| [Preventive measure] | [Name] | P1 | YYYY-MM-DD | [Link] |
| [Detection improvement] | [Name] | P2 | YYYY-MM-DD | [Link] |
| [Process improvement] | [Name] | P3 | YYYY-MM-DD | [Link] |

---

#### 10. Lessons Learned

_Key takeaways that should inform future architecture, process, or training decisions._

---

#### 11. Review Sign-off

| Role | Name | Date |
|------|------|------|
| Incident Commander | | |
| Engineering Lead | | |
| Security Lead | | |
