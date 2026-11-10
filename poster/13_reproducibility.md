# Reproduce the Work — MCP Gateway Poster 01

**Current code snapshot:** `f1f226feb0d527f27b90081806d7e9bd90ba0574`  
**Successful Python 3.12 main CI:** [run 38502413461](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/38502413461) (October 14, 2026 UTC)

```bash
git clone https://github.com/poojakira/mcp-agent-security-gateway.git
cd mcp-agent-security-gateway
git checkout f1f226feb0d527f27b90081806d7e9bd90ba0574
python -m pip install -e ".[dev,server]"
PYTHONPATH=src python -m pytest tests -q --cov=mcp_monitor --cov-report=term
```

Expected at this cited CI snapshot: **782 passed, 81.93% statement coverage**, 5,657 statements / 1,022 missed. The code-source collection inventory contains **69 named signatures**, plus **9 Elastic rules**, **21 core SIEM tests**, and **12 SIEM scenario tests**; inventory counts are not population-level recall.

**Archived October 4 historical run:** [37184196303](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/37184196303) at `008775c8878cc70c50247baa223da3256e093316`: 723 passed, 81.91% coverage, 55 named signatures. These values are not this active poster snapshot.

Cerberus pilot evidence and detector effectiveness are separate and unchanged. GitHub Actions results are scoped to the cited commit and environment.

## November 2026 verification and claim boundary

These reproduction steps intentionally pin the October evidence source; running them at the active branch head tests a different code state and must not be reported as the 782/81.93% poster measurement. The [parity workflow](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42740787837) previously rerendered and matched the committed poster image. The development [PR #167](https://github.com/poojakira/mcp-agent-security-gateway/pull/167) remains production NO-GO.
