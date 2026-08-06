# Security Audit — mcp-security-gateway-monitor

**Audit date:** 2026-08-05  
**Auditor:** agent/mcp_monitor (automated Strictness-10 review)  
**Branch:** agent/security-hardening-v1

---

## Summary

| Severity | Finding | Fixed in this branch |
|----------|---------|----------------------|
| HIGH | Rate limiter returns a decision but does NOT raise / block — callers must check the return value and callers in `run_dashboard.py` do not | Yes — `check_rate_limit()` added |
| MEDIUM | Dashboard output is entirely simulated (red-team catalog replay), not live telemetry — README did not state this clearly | Yes — SIMULATED_DATA notice added |
| MEDIUM | CI workflow uses mutable action tags (`@v4`, `@v5`, `@v3`, `@v6`) — susceptible to tag-moving supply-chain attacks | Yes — all actions pinned to commit SHAs |
| LOW | No `subprocess` calls with `shell=True` found — no fix needed | N/A |
| LOW | No hardcoded secrets found in source (test fixtures use the placeholder value `"secret"` for `MCP_API_KEY` — not a real credential) | N/A |
| INFO | No unauthenticated public HTTP endpoints that accept arbitrary input in the core layers — the FastAPI server (`production/server.py`) is an optional extra, not started by default | No fix needed |

---

## Detailed Findings

### FINDING-001 (HIGH): Rate limiter does not enforce blocking

**File:** `src/mcp_monitor/defense10/rate_limiter.py`

`RateLimiter.check()` returns a `RateLimitDecision` dataclass with `allowed=False` when a limit is
exceeded, but it does **not** raise an exception. Nothing in the default execution path
(`run_dashboard.py → AttackSimulator → FiveLayerDefense`) feeds the decision back into a hard block.
A caller that ignores the return value silently allows the over-limit request through.

**Fix applied:** Added `check_rate_limit(key: str) -> None` method that calls `check()` and raises
`RateLimitExceeded` (an `HTTPException` 429 subclass) when `allowed` is `False`. Callers in the
gateway path must use `check_rate_limit()` to enforce the limit at the boundary.

---

### FINDING-002 (MEDIUM): Dashboard metrics are simulated — not live telemetry

**File:** `run_dashboard.py`, `README.md`

`run_dashboard.py` runs the bundled `AttackSimulator.run_full_catalog()` against pre-canned payloads
and renders the results as a dashboard. The HTML output and terminal report display detection counts,
layer statistics, and timing metrics that are entirely derived from the simulator, not from monitoring
actual MCP traffic.

The README's "Honest status" section does mention the ~51% detection rate is "on the bundled
simulator", but there is no prominent notice at the top of the README or in the dashboard output
itself warning users that the numbers they see are generated/simulated.

**Fix applied:** SIMULATED_DATA notice added to the top of README.md.

---

### FINDING-003 (MEDIUM): CI uses mutable action tags — supply-chain risk

**File:** `.github/workflows/ci.yml`

Actions pinned only to floating version tags (`actions/checkout@v4`, `actions/setup-python@v5`, etc.)
allow a compromised upstream to push a new commit under the same tag and execute arbitrary code in
the CI pipeline.

**Fix applied:** All action references replaced with pinned commit SHAs. Tag retained as a comment
for readability.

---

### FINDING-004 (LOW / INFO): No `shell=True` subprocess calls found

Searched all Python files for `subprocess.run`, `subprocess.call`, `subprocess.Popen`,
`os.system`, `exec()`. Findings:

- `src/mcp_monitor/defense10/sandbox.py`: uses `subprocess.run(full, capture_output=True, …)` with
  `full` being a pre-built list — **no** `shell=True`. Safe.
- `benchmark/replay_evidence.py`: uses `subprocess.run(["git", "rev-parse", "HEAD"], …)` — **no**
  `shell=True`. Safe.
- `src/mcp_monitor/layers/orchestrator.py` and `src/mcp_monitor/defense10/corpus.py`:
  references to `"subprocess"` / `"os.system"` appear only as *strings inside payload lists* used
  for detection testing — not as actual calls. Safe.

No fix required.

---

### FINDING-005 (INFO): No hardcoded production secrets

Searched for `password=`, `token=`, `secret=`, `api_key=` literal assignments.  
`tests/test_production.py` uses `MCP_API_KEY="secret"` as a test fixture placeholder — this is a
test-only value passed to a test helper, not a real credential embedded in production code.

No fix required.

---

### FINDING-006 (INFO): No unauthenticated endpoints in default execution path

The FastAPI production server (`src/mcp_monitor/production/server.py`) is an **optional** extra
(`pip install -e ".[server]"`). It is not started by `run_dashboard.py` or the test suite by
default. Review authentication on that server separately before exposing it to untrusted networks.

---

## Files Changed in This Branch

| File | Change |
|------|--------|
| `src/mcp_monitor/defense10/rate_limiter.py` | Added `RateLimitExceeded` exception and `check_rate_limit()` method |
| `README.md` | Added SIMULATED_DATA notice |
| `.github/workflows/ci.yml` | Pinned all action tags to commit SHAs |
| `SECURITY_AUDIT.md` | This file (new) |
| `evidence_policy.json` | Evidence manifest (new) |
