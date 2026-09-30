# Reproduce the Work — Poster 01

> Evidence status: This Markdown companion reflects the latest verified code snapshot. The rendered poster PDF remains tied to its own printed historical commit/date.

**Repository:** `github.com/poojakira/mcp-agent-security-gateway`  
**Verified code snapshot:** `59eeac5221ab4eff3d5c5e421ccb46407de08037`

```powershell
git clone https://github.com/poojakira/mcp-agent-security-gateway.git
cd mcp-agent-security-gateway
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev,server]"
$env:PYTHONPATH="src"
python -m pytest tests -q --cov=mcp_monitor --cov-report=term
```

**Expected at the verified code snapshot:** `702 passed`; total statement coverage **82.76%** (5,324 statements, 918 missed).

Static counts:

```powershell
$env:PYTHONPATH="src"
python -c "from mcp_monitor.detectors import prompt_injection as p; print(len(p.INJECTION_PATTERNS))"   # 55
# 9 = count of [[rule]] in detection_rules/elastic_rules.toml
# 21 = def test_ in tests/test_siem.py
# 12 = test_* functions in tests/test_siem_scenarios.py
```

Credential/network telemetry can be reproduced with the tests in `tests/test_cerberus.py`, which cover HMAC fingerprint vectors, IPv4/IPv6 canonicalization, trusted-proxy behavior, closed event fields, zero-token semantics, and stable/distinct credential fingerprints.

**Evidence artifacts:** `VERIFIED_METRICS.md`, `evidence/mcp_replay_evidence.json`, `detection_rules/elastic_rules.toml`.  
**Authoritative CI:** GitHub Actions remains the authoritative environment for published test/coverage claims.
