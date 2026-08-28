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
  # Health check endpoint (port 8080 production API)
  curl -s http://gateway:8080/v1/health | jq .

  # Readiness check
  curl -s http://gateway:8080/v1/ready | jq .

  # Runtime metrics (includes error counters)
  curl -s http://gateway:8080/v1/metrics
  ```
- [ ] **Check logs** for immediate root cause:
  ```bash
  # Last 100 error-level logs (systemd)
  journalctl -u mcp-gateway --since "5 min ago" -p err

  # Or from the process stdout/log file:
  tail -n 100 gateway-monitor.log | grep -i error
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
# Check the process and its memory usage
ps aux | grep -i mcp | grep -v grep

# Restart the server process (the `mcp-gateway` entry point only starts the HTTP server)
# Stop the current process (Ctrl+C in its terminal, or kill <PID>), then restart:
mcp-gateway            # or: python -m mcp_monitor ... per your deployment

# If running under a supervisor (systemd/pm2/supervisord), restart the unit:
systemctl restart mcp-gateway
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
# Adjust detector/policy behavior via environment/config, then restart the server.
# The gateway is configured through environment variables and config files, not CLI subcommands.

# Example: relax a timeout in your environment/config, then restart the process:
#   edit .env / your config source
mcp-gateway            # restart the server so it re-reads config
# or under a supervisor:
systemctl restart mcp-gateway
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
# Identify which rule/detector is triggering from the audit log
grep "BLOCKED" gateway-monitor.log | tail -50 | \
  jq -r '.detector' | sort | uniq -c | sort -rn

# Adjust detection thresholds / rule config in your config source,
# then restart the server so it re-reads the config:
#   edit config (see RUNBOOK section 9, "Tuning Detection Thresholds")
mcp-gateway            # restart the server
# or under a supervisor:
systemctl restart mcp-gateway
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
# 1. Preserve evidence: snapshot the current audit log and WAL data
cp gateway-monitor.log "incident-$(date +%s).log"
cp -r /var/lib/mcp-gateway/ "forensic-$(date +%s)/" 2>/dev/null || true

# 2. Tighten detection: edit your config/env to enable strict thresholds and
#    add an emergency block pattern for the detected vector, then restart:
#    edit config (see RUNBOOK section 9)
mcp-gateway            # restart the server so it re-reads config
# or under a supervisor:
systemctl restart mcp-gateway

# 3. Rotate any potentially compromised credentials out-of-band
#    (in your secrets manager / .env), then restart the server to pick them up.
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
# Restore config from a known-good source (e.g. git), then restart the server
# so it re-reads the config. The gateway has no `config validate/reload` subcommand.
git -C /path/to/config checkout main -- .    # or copy known-good config into place
mcp-gateway            # restart the server
# or under a supervisor:
systemctl restart mcp-gateway

# Verify replicas are consistent by comparing the deployed config files/hashes
sha256sum /etc/mcp-gateway/config.* 2>/dev/null
```

---

### 6. Upstream Dependency Failure

**Symptoms:** Gateway healthy but cannot reach logging/metrics backends, audit trail gaps.

**Immediate Mitigation:**
```bash
# The gateway core is stdlib-only and continues operating even if
# logging/metrics backends are unreachable. Verify it is still serving:
curl -s http://gateway:8080/v1/health | jq .

# Check local audit/WAL storage isn't filling the disk
du -sh /var/lib/mcp-gateway/ 2>/dev/null
df -h

# If local storage is full, archive/rotate the audit log out of the way,
# then restart the server:
mv gateway-monitor.log "gateway-monitor-$(date +%s).log"
mcp-gateway            # restart the server
```

---

## Rollback Procedures

### Application Rollback

```bash
# 1. Identify the last known-good version/commit
git -C /path/to/mcp-agent-security-gateway log --oneline -10

# 2. Check out the previous known-good revision
git -C /path/to/mcp-agent-security-gateway checkout <known-good-sha>
pip install -e .          # reinstall the entry point from that revision

# 3. Restart the server and verify
mcp-gateway               # or restart via your supervisor
curl -s http://gateway:8080/v1/health | jq .
```

### Configuration Rollback

```bash
# 1. Restore the previous config from version control
git -C /path/to/config log --oneline -10
git -C /path/to/config checkout <COMMIT_SHA> -- .

# 2. Restart the server so it re-reads the restored config
mcp-gateway               # or: systemctl restart mcp-gateway
```

### Detection Rule / Policy Rollback

```bash
# Detection rules live in config, not a runtime API. Roll them back via VCS:
git -C /path/to/config checkout <known-good-sha> -- rules/   # adjust path

# Restart the server to apply, then verify readiness:
mcp-gateway
curl -s http://gateway:8080/v1/ready | jq .
```

### Emergency: Full System Rollback

For catastrophic failures affecting the entire deployment:

```bash
# 1. Check out the last known-good revision of code + config together
git checkout <known-good-sha>
pip install -e .

# 2. Restart the server process
mcp-gateway               # or restart via your supervisor

# 3. Verify
curl -s http://gateway:8080/v1/health | jq .
curl -s http://gateway:8080/v1/ready | jq .
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
