# Independent recheck of the current MCP archive candidate

PRODUCT: poojakira/mcp-agent-security-gateway
SOURCE: 4b6bb486d83f4410037113e64848a22e4a06f713
BRANCH: codex/local-workbench-20261116
PHASE: Exact-source independent verification after CI/container-build corrections
DECISION: PARTIAL for the complete master acceptance contract. The three prior runtime/provenance findings remain CLOSED at this source.

## Fresh executed checks

| Check | Actual result | Evidence |
|---|---|---|
| Actual workbench subset on Python 3.10.22 | 23 passed, zero failures/skips | `python310-tests.log`, `python310-junit.xml` |
| Independent engine/HTTP/Chromium adversarial checks | 22 passed, zero failed | `independent-checks.json`, `independent-checks.log` |
| Final engineering artifact hashes/source | All34 listed digests matched; manifest SHA matched clean checkout | First two independent checks |
| New wheel installed inside unrelated Git project | Actual read CONFIRMED_SUCCEEDED; source commit/status UNKNOWN | `unrelated-wheel-provenance.json`, `unrelated-wheel-install.log` |
| All current workflow files through actionlint1.7.7 | Exit0 | `actionlint.log` |

Wheel SHA256: `d21382a39c620cdb21e994766357ea4bf324f18e699fd455c8dd6a9df7c0ba30`. Its bytes were checked against the frozen source manifest before installation. An initial review log redirection raced output-directory creation, so actionlint did not execute in that attempt; after the directory existed, the actual actionlint command ran and passed.

The independent browser used new operator-supplied note text, observed its actual tool-side change, checked export redaction and exact source SHA, and captured fresh evidence. Other checks exercised repeat-count hashes/duplicate effects, malformed duplicate keys, disallowed metadata destination, absolute cross-workspace paths, alternate methods, actual crash/timeout UNKNOWN, Host/Origin/body/type/extra-field boundaries, safe hostile-HTML rendering and real request-driven throttling. Raw check outcomes, UTC times, screenshot and downloaded export are in this directory. The source checkout remained clean and unchanged.

Commands included:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=src /workspace/work/reviews/mcp-agent-security-gateway/venv310/bin/python -m pytest -p no:cacheprovider tests/test_workbench.py -q --junitxml=/workspace/work/reviews/mcp-agent-security-gateway/final-archive-recheck/python310-junit.xml
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src /workspace/work/tooling/venv/bin/python /workspace/work/reviews/mcp-agent-security-gateway/final-archive-recheck/independent_checks.py
/workspace/work/tooling/actionlint/actionlint -oneline
```

The wheel was installed using `pip install --no-deps --force-reinstall` in the unrelated-project venv, followed by calls to the installed package's real `provenance()` and `execute()` functions. No paid service, provider credential or new API key was used.

## Prior finding closure

| Prior finding | Disposition at4b6bb486 |
|---|---|
| Python3.10 asyncio timeout escapes reconciliation | CLOSED: actual timeout test passes on3.10.22 and outcome remains UNKNOWN |
| Installed wheel inherits unrelated Git HEAD | CLOSED: newly installed wheel returns UNKNOWN/UNKNOWN during a real successful read |
| Repeat count absent from configuration evidence | CLOSED: requested counts/effective allowlist are included and different counts produce distinct configuration hashes with actual effects |

Historical proofs remain in their original source-specific review directories. They are not presented as current results.

## CI, archive and operational limits

Source inspection and actionlint confirm a supported GitHub-context expression for evidence paths and explicit PR-head checkout in the local workbench workflow. The existing lint gate includes checksum-pinned actionlint. The Docker builder now installs Git for the actual Git-backed regression fixtures; the runtime stage does not add Git. These source checks do not establish that the current container image builds or runs successfully.

No Docker build was attempted in this independent recheck. Current exact-source container verification and actual remote CI results remain NOT VERIFIED here; earlier environment failures or earlier remote runs cannot be attributed to this source. The README uses the intended immutable evidence archive tag; public screenshot/tag accessibility requires the parent's actual publication check. No permanent evidence branch or release readiness is inferred from that URL.

The separate engineering manifest records829 passed, zero failures/skips,81.80446084% statement coverage, the unchanged77% threshold, and its own lint/type/browser/build/audit results. This review independently checked artifact consistency and the focused checks above; it did not repeat that entire suite.

Full current MCP conformance/cancellation/concurrency, credential lifecycle, output injection/PII handling, arbitrary-server OS containment, durable side-effect reconciliation, complete lock/build-source provenance, exhaustive legacy-document reconciliation, complete branch consolidation/protection visibility, and deployment-specific operational approval remain NOT VERIFIED or NOT IMPLEMENTED as documented. Removal of a few proven obsolete branches is not proof that whole-repository branch cleanup is finished. The product remains PARTIAL and is not production approved.

NEXT SAFE ACTION: Publish exact-source evidence under the immutable non-release archive tag, inspect actual exact-head remote CI/container outcomes, retain recovery references and unique work, and continue each remaining product independently.
