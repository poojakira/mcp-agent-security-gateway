> **Latest tested regression evidence:** SHA `a24f92c17f93d5c150eafe4ba7dce507ecb534b6`, [CI 43657370973](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43657370973): **1,245 passed, 6 skipped per Python 3.10/3.11/3.12; 5/5 jobs passed**. [Poster parity 43656574988](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43656574988) passed at that source SHA. Subsequent code/docs changes require new exact-head verification; historical 1,211-pass results below belong to a different commit. PRODUCTION NO-GO.

# Reproducibility — November 11, 2026 Phase 1–16 Poster

**Reviewed source SHA:** `43a72c8984bf9a472b9055d4f9e84cc759f61718` (stacked draft review branch).  
**Release state:** **PRODUCTION NO-GO**, no approved production manifest.

## Exact-head test evidence

- [Integrated 3-version matrix: 42971171992](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42971171992): per Python version 1,211 passed, 6 skipped; five integrated jobs passed.
- [Security Hygiene: 42971171965](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42971171965): configured tracked-file/history checks and Bandit threshold passed.
- [Python SBOM/advisories: 42971171775](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42971171775): CycloneDX installed-environment SBOM artifact and pip-audit public advisory check passed.
- [Protected MCP real Docker smoke: 42971171991](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42971171991): real offline import and tools/list handshake passed.

## Reproduce development source

```bash
git clone https://github.com/poojakira/mcp-agent-security-gateway.git
cd mcp-agent-security-gateway
git fetch origin security/phase1-16-protected-image-deps-20261110
git checkout 43a72c8984bf9a472b9055d4f9e84cc759f61718
python -m pip install -e ".[dev,oidc]"
python -m pytest tests -q
```

These commands describe reproduction; they are not proof of an additional local run. The workflow environments install publicly available dependencies, so a later resolution may differ. Real Docker and SBOM workflows must be run separately and have their own constraints.

## Poster generation

```bash
POSTER_BROWSER="$(command -v chromium || command -v google-chrome)" python poster/render_poster.py
```

The original poster binary files belong to their prior snapshot until regenerated and independently visually reviewed. The read-only poster workflow publishes new PNG/PDF **as CI artifacts**, not by rewriting GitHub source via a workflow token. Existing committed binaries should not be presented as current without parity validation.

## Explicit exclusions

No external provider API key, paid service, bank, booking site or healthcare platform is required in the cited offline tests. This does not mean the optional HTTP production service has no operator authentication, nor does it establish complete secret removal from remote systems. No field precision/recall, current coverage percentage, independent pentest or production certification is claimed.
