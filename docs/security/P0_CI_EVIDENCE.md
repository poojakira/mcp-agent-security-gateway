# P0 CI and verification evidence

Baseline branch fetched before modifications: `fix/evidence-provenance-20261114`; exact SHA `f7bec6d599015a1f976fc85290868a3293c89ec4`.

GitHub Actions API confirmed [integrated run 43758431828](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43758431828) successful on this exact SHA; job API confirmed nine successful jobs (three Python regressions, lab security, Phase 5/9/14 Docker, public manifest and official filesystem MCP). [Poster run 43758431857](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/43758431857) also successful. These are baseline results, not remediation results.

Reproduction: archive baseline source into disposable `/tmp/p0-baseline`, run new boundary tests with baseline PYTHONPATH. Observed **10 failed, 1 passed**. Failures cover acknowledgment-only completion, absent evidence persistence, mutable snapshot, untrusted journal files, existing-file bootstrap and stale queued dispatch. Missing new API/table failures establish missing controls, not remote exploits. Queue tests timed out because baseline dispatched; target counter records the unauthorized effect. Stdlib reproduction also observed COMPLETED with no external operation performed.

Local execution environment: Linux, disposable workspace, Python 3.12.14 initially; isolated downloaded Python 3.10.22 and 3.11.18 for matrix verification; Docker engine 29.9.2. No paid APIs or production data. Exact final source SHA/results will be appended after freezing the implementation.

Infrastructure failures are not hidden: sandbox denied local listeners; reruns used authorized disposable network access. Parallel matrix exhausted workspace space and produced fixture creation errors. Affected runs must be rerun after cleanup. Initial webhook tests failed because they mocked the replaced urllib transport; payload/alert assertions retained against secured POST transport. Initial Docker fixtures could not start non-root because copied checkout source was unreadable; explicit COPY permissions corrected that defect. General gateway image build failed TLS validation at package index through environment proxy; verification was not disabled.

Dependency audit initially found 12 advisory records in pip 25.0.1 (including duplicated advisory IDs), a local verification-tool dependency. Upgraded local pip; subsequent report: **No known vulnerabilities found**. This is the installed Python environment, not an image or license approval. CycloneDX environment SBOM generated separately; no zero-dependency artifact invented.

Secret triage: initial scan of **1,691 reachable blobs** reported seven blobs; all matched one published AWS documentation example fingerprint `1a5d44a2dca19669d72edf4c4f1c27c4c1ca4b4408fbb17f6ce4ad452d78ddb3`, used in attack fixtures and detector tests. The exact-byte fingerprint is exempted; nearby EXAMPLE/PLACEHOLDER text never exempts a token. No credential values are recorded here. Final count changes when commits are added. This bounded scan is not proof of absent credentials and does not establish issuer revocation.

Independent verification limit: this agent performed a separate adversarial code-path pass and tests, not an independent human assessment. Production acceptance and issuer actions remain blocked.
