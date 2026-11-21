# Remediation report

Branch codex/local-workbench-20261116. Local fixing source 31758f467f8d17ef500f1e0f2c09c22f1814aa23. Review baseline d2e7b6ea7c1a1f9cb0fb71f73d0a692d8fa0410c.

- **MCP-01** A pip install piped to tail could return success on failed installation. CI invokes pip directly.
- **MCP-02** The collection pipeline disregarded pytest’s status. The patched step checks the status before counting and retains the ten-test minimum.
- **MCP-03** The coverage matrix failed to load its Elastic TOML in a wheel-only install. The wheel packages the canonical data file and the lookup supports checkout, installed package and the explicit environment override.
- **MCP-04** Both files referenced a missing branch-cleanup.json in the evidence archive. HTTP returned 404 and the named object was absent from Git. The links now point to the existing immutable manifest or cleanup record.

Read [documentation parity](DOCUMENTATION_PARITY.md) for the evidence pins. Historical poster figures and images retain their original date and provenance.
