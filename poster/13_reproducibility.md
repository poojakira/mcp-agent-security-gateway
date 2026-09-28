# Reproduce the Work — Poster 01

**Repository:** `github.com/poojakira/mcp-agent-security-gateway`
**Environment (this verification):** Windows, CPython 3.12.10, fresh venv. HEAD `c68e200d320ce68793096598e516b4d015bc21ad`.

```powershell
git clone https://github.com/poojakira/mcp-agent-security-gateway.git
cd mcp-agent-security-gateway
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev,server]"
$env:PYTHONPATH="src"
python -m pytest tests -q --cov=mcp_monitor --cov-report=term
```

**Expected (observed 2026-09-27):** `659 passed`, TOTAL coverage `82%` (4804 stmts, 880 missed).

Static counts:
```powershell
$env:PYTHONPATH="src"
python -c "from mcp_monitor.detectors import prompt_injection as p; print(len(p.INJECTION_PATTERNS))"   # 55
# 9 = count of ^[[rule]] in detection_rules/elastic_rules.toml
# 21 = def test_ in tests/test_siem.py ; 7 = def test_ in tests/test_siem_scenarios.py
```

**Evidence artifacts in repo:** `VERIFIED_METRICS.md`, `evidence/mcp_replay_evidence.json`, `detection_rules/elastic_rules.toml`.
**Authoritative CI:** GitHub Actions is the repo's authoritative environment for published test/coverage claims.
