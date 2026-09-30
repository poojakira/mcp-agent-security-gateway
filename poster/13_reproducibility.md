# Reproduce the Work - Poster 01

**Repository:** `github.com/poojakira/mcp-agent-security-gateway`  
**Verified code snapshot:** `8427f9ecafd3438a86775a7ceaf809f4ee051b5b`  
**GitHub Actions CI:** `36783059917`

```powershell
git clone https://github.com/poojakira/mcp-agent-security-gateway.git
cd mcp-agent-security-gateway
git checkout 8427f9ecafd3438a86775a7ceaf809f4ee051b5b
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev,server]"
$env:PYTHONPATH="src"
python -m pytest tests -q --cov=mcp_monitor --cov-report=term
```

Expected at the cited snapshot:

- **718 passed**
- **82.46% statement coverage**
- 5,524 statements / 969 missed

Static evidence:

- prompt-injection collection: **55**
- Elastic `[[rule]]` records: **9**
- core SIEM tests: **21**
- SIEM scenario tests: **12**

GitHub Actions is the authoritative environment for the published test and coverage values.
