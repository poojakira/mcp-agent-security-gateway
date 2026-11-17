# Independent verification of the publication candidate

PRODUCT: poojakira/mcp-agent-security-gateway
SOURCE: c36664757c20bbc4c9d1614ec0c9e7c9e10558cd
BRANCH: codex/local-workbench-20261116
PHASE: Fresh independent checks after publication-identity correction
DECISION: PARTIAL for the complete master acceptance contract. The three prior defects remain CLOSED on this exact source.

## Source and evidence identity

The publication candidate and preserved corrected candidate c8dd416f6f5b57a0f34e3630400fc78538bba47f both have tree 17f9c227a91373fe5cc13117f18215fcca0e88ad. This was independently checked with Git and recorded in `tree-identity.json`. The parent reports that private-email protection rejected earlier publication and that unpublished references were preserved. This review made no source or remote changes.

All checks below were freshly executed against the new publication source. The prior defect report and remediation results remain associated with their original commits in the parent review directories.

## Fresh executed results

| Check | Result | Evidence |
|---|---|---|
| Actual workbench subset on Python 3.10.22 | 23 passed, 0 failed/skipped | `python310-tests.log`, `python310-junit.xml` |
| Independent real-engine, HTTP and Chromium browser checks | 22 passed, 0 failed | `independent-checks.json`, `independent-checks.log` |
| Final engineering manifest artifact checksums and exact clean source | All 23 listed artifact hashes matched; source and clean checkout matched | First two checks in `independent-checks.json` |
| Newly built wheel installed under unrelated Git project | Actual read CONFIRMED_SUCCEEDED; source commit/status correctly UNKNOWN | `unrelated-wheel-provenance.json`, `unrelated-wheel-install.log` |

The newly built wheel hash is `3e77ae329edacd9cd70b3354dfe8fa7e72952c6fb79fbe9ce5ad7171256f1063`, matching the frozen source's final manifest. Installation occurred only after the parent confirmed the new build and manifest were frozen. No superseded wheel was used for this check.

The independent browser supplied a new note through the editable request field, observed its actual tool-side update, downloaded a redacted export and checked its current source commit. It also verified actual hostile-HTML denial and safe text rendering. Other executed cases covered duplicate JSON keys, metadata destination refusal, cross-workspace paths, alternate methods, process crash/timeout uncertainty, differing repeat counts and real duplicate effects, Host/Origin, extra fields, oversized/deep bodies, content type and request-driven rate limiting. Screenshots and downloaded export are newly captured in this directory.

Commands:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=src /workspace/work/reviews/mcp-agent-security-gateway/venv310/bin/python -m pytest -p no:cacheprovider tests/test_workbench.py -q --junitxml=/workspace/work/reviews/mcp-agent-security-gateway/publication-recheck/python310-junit.xml
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src /workspace/work/tooling/venv/bin/python /workspace/work/reviews/mcp-agent-security-gateway/publication-recheck/independent_checks.py
/workspace/work/reviews/mcp-agent-security-gateway/unrelated-project/.venv/bin/python -m pip install --no-deps --force-reinstall /workspace/work/evidence/mcp-agent-security-gateway/final/artifacts/mcp_security_gateway_monitor-0.1.0-py3-none-any.whl
```

The installed package's `provenance()` and actual `execute()` were then called inside that unrelated project; the recorded JSON contains both outcomes. UTC execution times are in the check JSON/JUnit and generated review manifest. The source checkout was clean before and after.

## Prior findings at this source

| Finding | Fresh disposition |
|---|---|
| F1: Python 3.10 asyncio timeout escapes reconciliation | CLOSED: actual timeout regression passes on Python 3.10.22 |
| F2: installed wheel inherits unrelated Git HEAD | CLOSED: actual newly built installed wheel returns UNKNOWN/UNKNOWN, including during a successful real read |
| F3: repeat count omitted from configuration evidence | CLOSED: repeated actual appends have distinct complete configuration hashes and report requested counts |

The full engineering regression is separately recorded as 829 passed with no failures/skips in the exact-source final manifest. This review verified its artifact consistency and independently ran the focused checks above; it did not independently repeat that entire suite.

## Remaining contract limits

The complete release remains PARTIAL. The workbench exposes a bounded first-party subprocess rather than arbitrary-server OS containment. Current full MCP conformance/cancellation/concurrency, credential lifecycle, indirect tool-output injection/PII filtering, durable reconciliation, complete transitive locks/build-source metadata, exhaustive legacy-document reconciliation, branch consolidation/protection visibility and deployment-specific operational approval remain NOT IMPLEMENTED or NOT VERIFIED as documented. Remote CI and the planned evidence-ref screenshot's public accessibility still need actual publication checks. No production-ready or VERIFIED LOCAL RELEASE CANDIDATE designation is warranted.

NEXT SAFE ACTION: Publish this frozen source and its separately generated exact-SHA evidence for review, inspect actual remote CI/artifacts, preserve unique and ambiguous work, and continue the next product independently.
