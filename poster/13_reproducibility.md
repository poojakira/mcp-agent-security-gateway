# Reproduce the Work - Poster 01

**Repository:** `github.com/poojakira/mcp-agent-security-gateway`  
**Verified code snapshot:** `008775c8878cc70c50247baa223da3256e093316`  
**GitHub Actions CI:** `37184196303`

```powershell
git clone https://github.com/poojakira/mcp-agent-security-gateway.git
cd mcp-agent-security-gateway
git checkout 008775c8878cc70c50247baa223da3256e093316
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev,server]"
$env:PYTHONPATH="src"
python -m pytest tests -q --cov=mcp_monitor --cov-report=term
```

Expected at the cited snapshot:

- **723 passed**
- **81.91% statement coverage**
- 5,644 statements / 1,021 missed

Static evidence:

- prompt-injection collection: **55**
- Elastic `[[rule]]` records: **9**
- core SIEM tests: **21**
- SIEM scenario tests: **7**

GitHub Actions is the authoritative environment for the published test and coverage values.


## Claim audit and rendered-source boundary, October 13, 2026 UTC

The reviewed printed claims, source and test commit anchors, CI dates and benchmark limitations are in `verified_claims.json`. The PDF is generated from that manifest and the PNG is rasterized from the same page by `render_poster.py`. Source inventory, dated CI and separate reported experiments must not be combined into one result. Earlier artifact versions remain in Git history; these corrections do not assert production readiness.

Offline poster rendering: `python -m pip install reportlab==4.4.9 PyMuPDF==1.26.6`, then `python poster/render_poster.py`. The font is bundled with the pinned ReportLab package; no browser or network fetch is used during rendering.
