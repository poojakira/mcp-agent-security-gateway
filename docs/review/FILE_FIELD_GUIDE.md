> **Evidence reconciliation (2026-11-11; historical phase/snapshot):** Historical results below retain their original dates and denominators. Latest tested Phase 1–16 development SHA is `43a72c8984bf9a472b9055d4f9e84cc759f61718` ([CI](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42971171992): 1,211 passed, 6 skipped per Python version), **not** a merged or production-approved release. Offline research tests require no paid provider or provider-issued API keys; deployed HTTP authentication and unverified real credential revocation remain separate. See [operating restrictions](../../PRODUCTION.md) and [release evidence](../../docs/review/PHASE1_16_RELEASE_CANDIDATE_NO_GO_20261110.md).

# Repository file field guide

> **Integration-documentation review (2026-11-09):** This map describes tracked repository files and sampled execution paths. Optional integrations, tests and prototype adapters must not be conflated with the active supported runtime. The development integration is [draft PR #167](https://github.com/poojakira/mcp-agent-security-gateway/pull/167), **not a production-approved release**.
**Snapshot:** [`a3359e47d68c`](https://github.com/poojakira/mcp-agent-security-gateway/commit/a3359e47d68c231e20e62fb4063eb552d1c43b46) on draft PR #148. **Inventory:** 225 tracked files (including binary assets). This is an exhaustive **path inventory at this commit**, not an assertion that every file has passed a line-by-line security audit. Descriptions of critical MCP enforcement files are grounded in the previous source review; most other descriptions summarize the file's apparent role from path/name and must be confirmed against implementation before making detailed claims.

## How to explain the product

The MCP client calls the Python **stdio proxy**. Its protocol parser, detector, policy engine, and optional ACL guard evaluate routed messages; permitted requests go to a downstream MCP server, and eligible responses are inspected before returning to the client. The existing real-filesystem smoke test runs an **external** MCP filesystem server, not a server authored by this project. See [the execution graph](REPOSITORY_DEPENDENCY_MAP.md), [attack evidence](ATTACK_CONTROL_EVIDENCE.md), and [production gaps](REAL_WORLD_PROTOTYPE_ACCEPTANCE.md).

## Reading rule

Each link points to the exact snapshot. **Description** explains the file's topic, not proof that its intended feature is production-grade. Binary PDFs/images cannot be interpreted as code. Tests demonstrate only their stated scenarios; security controls are effective only on integrated/routed paths.

## GitHub automation and repository controls (13)

| File (click to open) | What you will find |
|---|---|
| [`.github/CODEOWNERS`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/.github/CODEOWNERS) | File-ownership rules. |
| [`.github/dependabot.yml`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/.github/dependabot.yml) | Dependency update automation. |
| [`.github/format-trigger.txt`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/.github/format-trigger.txt) | GitHub repository automation/configuration file. |
| [`.github/scripts/check_bandit.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/.github/scripts/check_bandit.py) | GitHub repository automation/configuration file. |
| [`.github/scripts/check_pip_audit.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/.github/scripts/check_pip_audit.py) | GitHub repository automation/configuration file. |
| [`.github/workflows/appsec-focused.yml`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/.github/workflows/appsec-focused.yml) | GitHub Actions workflow for appsec focused. |
| [`.github/workflows/ci.yml`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/.github/workflows/ci.yml) | GitHub Actions workflow for ci. |
| [`.github/workflows/poster-artifact-parity.yml`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/.github/workflows/poster-artifact-parity.yml) | GitHub Actions workflow for poster artifact parity. |
| [`.github/workflows/production-gate.yml`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/.github/workflows/production-gate.yml) | GitHub Actions workflow for production gate. |
| [`.github/workflows/production-policy.yml`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/.github/workflows/production-policy.yml) | GitHub Actions workflow for production policy. |
| [`.github/workflows/real-mcp-smoke.yml`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/.github/workflows/real-mcp-smoke.yml) | GitHub Actions workflow for real mcp smoke. |
| [`.github/workflows/release.yml`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/.github/workflows/release.yml) | GitHub Actions workflow for release. |
| [`.github/workflows/security-hygiene.yml`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/.github/workflows/security-hygiene.yml) | GitHub Actions workflow for security hygiene. |

## Project entry points and documentation (28)

| File (click to open) | What you will find |
|---|---|
| [`.gitattributes`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/.gitattributes) | Repository asset/configuration: . |
| [`.gitignore`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/.gitignore) | Local files excluded from Git tracking; not a secrets erasure mechanism. |
| [`.gitleaksignore`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/.gitleaksignore) | Scoped suppressions for prior secret-scanner findings. |
| [`.mailmap`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/.mailmap) | Repository asset/configuration: . |
| [`CHANGELOG.md`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/CHANGELOG.md) | Recorded project changes. |
| [`CONTRIBUTING.md`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/CONTRIBUTING.md) | Contribution and development instructions. |
| [`Dockerfile`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/Dockerfile) | Container build specification. |
| [`INCIDENT_RUNBOOK.md`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/INCIDENT_RUNBOOK.md) | Incident investigation and response procedures. |
| [`LICENSE`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/LICENSE) | Repository license terms. |
| [`MCP_Gateway_Poster.pdf`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/MCP_Gateway_Poster.pdf) | Published poster PDF; binary asset. |
| [`PRODUCTION.md`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/PRODUCTION.md) | Deployment-specific requirements and restrictions. |
| [`PROVENANCE.md`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/PROVENANCE.md) | Provenance information and source/claim traceability. |
| [`README.md`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/README.md) | Main project overview, setup, architecture, and evidence caveats. |
| [`RESEARCH_REPORT.md`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/RESEARCH_REPORT.md) | Technical research, evaluation and limitations. |
| [`RESUME_EVIDENCE.md`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/RESUME_EVIDENCE.md) | Project claims appropriate for resume use and their evidence. |
| [`RUNBOOK.md`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/RUNBOOK.md) | Operational setup and execution procedures. |
| [`SECURITY.md`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/SECURITY.md) | Security reporting and repository security guidance. |
| [`SECURITY_AUDIT.md`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/SECURITY_AUDIT.md) | Security audit findings and risk notes. |
| [`SECURITY_AUDIT_2026-09-30.md`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/SECURITY_AUDIT_2026-09-30.md) | Repository asset/configuration: SECURITY AUDIT 2026 09 30. |
| [`THREAT_MODEL.md`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/THREAT_MODEL.md) | Assets, attackers, trust boundaries, threats and mitigations. |
| [`VERIFIED_METRICS.md`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/VERIFIED_METRICS.md) | Dated test and coverage evidence; not general detection efficacy. |
| [`docker-compose.detection-lab.yml`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/docker-compose.detection-lab.yml) | Detection-lab container stack wiring. |
| [`docker-compose.yml`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/docker-compose.yml) | Local container service wiring. |
| [`evidence_policy.json`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/evidence_policy.json) | Evidence/claim policy data. |
| [`locustfile.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/locustfile.py) | Load-test scenarios and traffic generation. |
| [`pyproject.toml`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/pyproject.toml) | Python package metadata, dependency and tool configuration. |
| [`run_dashboard.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/run_dashboard.py) | Dashboard launcher. |
| [`run_realtime.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/run_realtime.py) | Real-time application launcher. |

## Benchmark and performance evaluation (4)

| File (click to open) | What you will find |
|---|---|
| [`benchmark/replay_evidence.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/benchmark/replay_evidence.py) | Benchmark script: replay evidence. |
| [`benchmark/tool_call_latency.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/benchmark/tool_call_latency.py) | Benchmark script: tool call latency. |
| [`benchmarks/enforcement_regression.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/benchmarks/enforcement_regression.py) | Benchmark script: enforcement regression. |
| [`benchmarks/perf_gate.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/benchmarks/perf_gate.py) | Benchmark script: perf gate. |

## Native inspection implementations (14)

| File (click to open) | What you will find |
|---|---|
| [`cpp/.gitignore`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/cpp/.gitignore) | Local files excluded from Git tracking; not a secrets erasure mechanism. |
| [`cpp/CMakeLists.txt`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/cpp/CMakeLists.txt) | C++ source/build: CMakeLists. |
| [`cpp/Makefile`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/cpp/Makefile) | C++ source/build: Makefile. |
| [`cpp/README.md`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/cpp/README.md) | C++ documentation: README. |
| [`cpp/include/mcp_inspect.hpp`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/cpp/include/mcp_inspect.hpp) | C++ source/build: mcp inspect. |
| [`cpp/src/main.cpp`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/cpp/src/main.cpp) | C++ source/build: main. |
| [`cpp/tests/test_inspect.cpp`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/cpp/tests/test_inspect.cpp) | C++ test: test inspect. |
| [`rust/.gitignore`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/rust/.gitignore) | Local files excluded from Git tracking; not a secrets erasure mechanism. |
| [`rust/Cargo.lock`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/rust/Cargo.lock) | Rust build/metadata: Cargo. |
| [`rust/Cargo.toml`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/rust/Cargo.toml) | Rust build/metadata: Cargo. |
| [`rust/LICENSE`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/rust/LICENSE) | Rust build/metadata: LICENSE. |
| [`rust/README.md`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/rust/README.md) | Rust documentation: README. |
| [`rust/src/lib.rs`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/rust/src/lib.rs) | Rust source: lib. |
| [`rust/src/main.rs`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/rust/src/main.rs) | Rust source: main. |

## Deployment and detection lab (11)

| File (click to open) | What you will find |
|---|---|
| [`deploy/k8s/README.md`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/deploy/k8s/README.md) | Kubernetes deployment instructions: README. |
| [`deploy/k8s/configmap.yaml`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/deploy/k8s/configmap.yaml) | Kubernetes deployment manifest: configmap. |
| [`deploy/k8s/deployment.yaml`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/deploy/k8s/deployment.yaml) | Kubernetes deployment manifest: deployment. |
| [`deploy/k8s/hpa.yaml`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/deploy/k8s/hpa.yaml) | Kubernetes deployment manifest: hpa. |
| [`deploy/k8s/namespace.yaml`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/deploy/k8s/namespace.yaml) | Kubernetes deployment manifest: namespace. |
| [`deploy/k8s/pvc.yaml`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/deploy/k8s/pvc.yaml) | Kubernetes deployment manifest: pvc. |
| [`deploy/k8s/secret.example.yaml`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/deploy/k8s/secret.example.yaml) | Kubernetes deployment manifest: secret.example. |
| [`deploy/k8s/service.yaml`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/deploy/k8s/service.yaml) | Kubernetes deployment manifest: service. |
| [`detection_lab/README.md`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/detection_lab/README.md) | Local detection lab instructions: README. |
| [`detection_lab/filebeat.yml`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/detection_lab/filebeat.yml) | Local detection lab configuration: filebeat. |
| [`detection_rules/elastic_rules.toml`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/detection_rules/elastic_rules.toml) | Elastic security detection-rule definitions. |

## Documentation, evidence and review (26)

| File (click to open) | What you will find |
|---|---|
| [`docs/API_VERSIONING.md`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/docs/API_VERSIONING.md) | Documentation: API VERSIONING. |
| [`docs/APPSEC_ASSESSMENT_2026-10-05.md`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/docs/APPSEC_ASSESSMENT_2026-10-05.md) | Documentation: APPSEC ASSESSMENT 2026 10 05. |
| [`docs/APPSEC_CASE_STUDY.md`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/docs/APPSEC_CASE_STUDY.md) | Documentation: APPSEC CASE STUDY. |
| [`docs/DOCKER_BUILD.md`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/docs/DOCKER_BUILD.md) | Documentation: DOCKER BUILD. |
| [`docs/ENFORCEMENT_BENCHMARK_2026-10-09.md`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/docs/ENFORCEMENT_BENCHMARK_2026-10-09.md) | Documentation: ENFORCEMENT BENCHMARK 2026 10 09. |
| [`docs/OPERATIONAL_INCIDENT_RESPONSE_MEASUREMENT.md`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/docs/OPERATIONAL_INCIDENT_RESPONSE_MEASUREMENT.md) | Documentation: OPERATIONAL INCIDENT RESPONSE MEASUREMENT. |
| [`docs/PERFORMANCE_BASELINE.md`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/docs/PERFORMANCE_BASELINE.md) | Documentation: PERFORMANCE BASELINE. |
| [`docs/RECRUITER_DEMO_60S.md`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/docs/RECRUITER_DEMO_60S.md) | Documentation: RECRUITER DEMO 60S. |
| [`docs/RECRUITER_EVIDENCE_AUDIT_2026-10-09.md`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/docs/RECRUITER_EVIDENCE_AUDIT_2026-10-09.md) | Documentation: RECRUITER EVIDENCE AUDIT 2026 10 09. |
| [`docs/VERIFICATION_STATUS_2026-10-09.md`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/docs/VERIFICATION_STATUS_2026-10-09.md) | Documentation: VERIFICATION STATUS 2026 10 09. |
| [`docs/archive/HISTORICAL_EVIDENCE.md`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/docs/archive/HISTORICAL_EVIDENCE.md) | Documentation: HISTORICAL EVIDENCE. |
| [`docs/detection/TUNING_LOG.md`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/docs/detection/TUNING_LOG.md) | Documentation: TUNING LOG. |
| [`docs/detection/coverage_matrix.json`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/docs/detection/coverage_matrix.json) | Saved data/measurement: coverage matrix. |
| [`docs/detection/coverage_matrix.md`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/docs/detection/coverage_matrix.md) | Documentation: coverage matrix. |
| [`docs/detection/fixtures/synthetic_events.json`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/docs/detection/fixtures/synthetic_events.json) | Saved data/measurement: synthetic events. |
| [`docs/detection/latency_bench.json`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/docs/detection/latency_bench.json) | Saved data/measurement: latency bench. |
| [`docs/detection/latency_bench.md`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/docs/detection/latency_bench.md) | Documentation: latency bench. |
| [`docs/detection/precision_recall.json`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/docs/detection/precision_recall.json) | Saved data/measurement: precision recall. |
| [`docs/detection/precision_recall.md`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/docs/detection/precision_recall.md) | Documentation: precision recall. |
| [`docs/evidence/RESUME_EVIDENCE.md`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/docs/evidence/RESUME_EVIDENCE.md) | Documentation: RESUME EVIDENCE. |
| [`docs/license-history/LICENSE-BEFORE-2026-10-13.txt`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/docs/license-history/LICENSE-BEFORE-2026-10-13.txt) | Documentation support asset. |
| [`docs/policy/ACL_CDC_GUARD.md`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/docs/policy/ACL_CDC_GUARD.md) | Documentation: ACL CDC GUARD. |
| [`docs/policy/POLICY_AS_CODE.md`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/docs/policy/POLICY_AS_CODE.md) | Documentation: POLICY AS CODE. |
| [`docs/review/ATTACK_CONTROL_EVIDENCE.md`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/docs/review/ATTACK_CONTROL_EVIDENCE.md) | Attack-to-control/function/file/test mapping. |
| [`docs/review/REAL_WORLD_PROTOTYPE_ACCEPTANCE.md`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/docs/review/REAL_WORLD_PROTOTYPE_ACCEPTANCE.md) | Reviewer questions, test reproduction and operational gaps. |
| [`docs/review/REPOSITORY_DEPENDENCY_MAP.md`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/docs/review/REPOSITORY_DEPENDENCY_MAP.md) | Logical MCP execution/module graph with verification references. |

## Generated evidence and policy definitions (6)

| File (click to open) | What you will find |
|---|---|
| [`evidence/generated/mcp_replay_evidence.json`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/evidence/generated/mcp_replay_evidence.json) | Repository asset/configuration: mcp replay evidence. |
| [`policy/rego/README.md`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/policy/rego/README.md) | Policy-as-code documentation: README. |
| [`policy/rego/egress.rego`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/policy/rego/egress.rego) | Policy-as-code source/test: egress. |
| [`policy/rego/egress_test.rego`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/policy/rego/egress_test.rego) | Policy-as-code source/test: egress test. |
| [`policy/rego/tool_authorization.rego`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/policy/rego/tool_authorization.rego) | Policy-as-code source/test: tool authorization. |
| [`policy/rego/tool_authorization_test.rego`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/policy/rego/tool_authorization_test.rego) | Policy-as-code source/test: tool authorization test. |

## Poster and visuals (7)

| File (click to open) | What you will find |
|---|---|
| [`poster/01_research_brief.md`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/poster/01_research_brief.md) | Research poster's technical scope and dated evidence. |
| [`poster/02_claim_ledger.md`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/poster/02_claim_ledger.md) | Claim-by-claim evidence ledger for poster. |
| [`poster/03_verified_metrics.md`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/poster/03_verified_metrics.md) | Dated poster metrics, source and limits. |
| [`poster/13_reproducibility.md`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/poster/13_reproducibility.md) | Commands for reproducing poster snapshot evidence. |
| [`poster/poster.png`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/poster/poster.png) | Rendered poster image; binary asset. |
| [`poster/poster_36x48.pdf`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/poster/poster_36x48.pdf) | Rendered poster PDF; binary asset. |
| [`poster/render_poster.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/poster/render_poster.py) | Generates rendered poster files from source material. |

## Utility scripts (3)

| File (click to open) | What you will find |
|---|---|
| [`scripts/measure_incident_response.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/scripts/measure_incident_response.py) | Utility script: measure incident response. |
| [`scripts/recruiter_demo.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/scripts/recruiter_demo.py) | Utility script: recruiter demo. |
| [`scripts/workflow_security_scan.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/scripts/workflow_security_scan.py) | Utility script: workflow security scan. |

## Python gateway implementation (71)

| File (click to open) | What you will find |
|---|---|
| [`src/mcp_monitor/__init__.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/__init__.py) | Python   init  .py module: package exports. |
| [`src/mcp_monitor/advanced/__init__.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/advanced/__init__.py) | Python advanced module: package exports. |
| [`src/mcp_monitor/advanced/canary.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/advanced/canary.py) | Python advanced module: canary. |
| [`src/mcp_monitor/advanced/correlation.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/advanced/correlation.py) | Python advanced module: correlation. |
| [`src/mcp_monitor/advanced/drift.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/advanced/drift.py) | Python advanced module: drift. |
| [`src/mcp_monitor/advanced/invariants.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/advanced/invariants.py) | Python advanced module: invariants. |
| [`src/mcp_monitor/advanced/manifest.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/advanced/manifest.py) | Python advanced module: manifest. |
| [`src/mcp_monitor/audit/__init__.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/audit/__init__.py) | Python audit module: package exports. |
| [`src/mcp_monitor/audit/log.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/audit/log.py) | Audit-log implementation (read in context of directory). |
| [`src/mcp_monitor/audit/wal.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/audit/wal.py) | Write-ahead log support. |
| [`src/mcp_monitor/client.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/client.py) | Python client.py module: client. |
| [`src/mcp_monitor/dashboard/__init__.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/dashboard/__init__.py) | Python dashboard module: package exports. |
| [`src/mcp_monitor/dashboard/report.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/dashboard/report.py) | Python dashboard module: report. |
| [`src/mcp_monitor/dashboard/terminal.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/dashboard/terminal.py) | Python dashboard module: terminal. |
| [`src/mcp_monitor/defense10/__init__.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/defense10/__init__.py) | Python defense10 module: package exports. |
| [`src/mcp_monitor/defense10/corpus.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/defense10/corpus.py) | Python defense10 module: corpus. |
| [`src/mcp_monitor/defense10/dataset.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/defense10/dataset.py) | Python defense10 module: dataset. |
| [`src/mcp_monitor/defense10/egress_proxy.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/defense10/egress_proxy.py) | Python defense10 module: egress proxy. |
| [`src/mcp_monitor/defense10/features.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/defense10/features.py) | Python defense10 module: features. |
| [`src/mcp_monitor/defense10/honeypot.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/defense10/honeypot.py) | Python defense10 module: honeypot. |
| [`src/mcp_monitor/defense10/ml_classifier.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/defense10/ml_classifier.py) | Python defense10 module: ml classifier. |
| [`src/mcp_monitor/defense10/network_monitor.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/defense10/network_monitor.py) | Python defense10 module: network monitor. |
| [`src/mcp_monitor/defense10/orchestrator10.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/defense10/orchestrator10.py) | Python defense10 module: orchestrator10. |
| [`src/mcp_monitor/defense10/rate_limiter.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/defense10/rate_limiter.py) | Python defense10 module: rate limiter. |
| [`src/mcp_monitor/defense10/sandbox.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/defense10/sandbox.py) | Python defense10 module: sandbox. |
| [`src/mcp_monitor/detectors/__init__.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/detectors/__init__.py) | Python detectors module: package exports. |
| [`src/mcp_monitor/detectors/exfiltration.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/detectors/exfiltration.py) | Sensitive-data exfiltration signal detection. |
| [`src/mcp_monitor/detectors/pii_detector.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/detectors/pii_detector.py) | PII pattern detection. |
| [`src/mcp_monitor/detectors/prompt_injection.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/detectors/prompt_injection.py) | Heuristic prompt-injection detector. |
| [`src/mcp_monitor/detectors/shadow_server.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/detectors/shadow_server.py) | Unrecognized MCP-server/capability detection. |
| [`src/mcp_monitor/layers/__init__.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/layers/__init__.py) | Python layers module: package exports. |
| [`src/mcp_monitor/layers/egress.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/layers/egress.py) | Python layers module: egress. |
| [`src/mcp_monitor/layers/kernel.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/layers/kernel.py) | Python layers module: kernel. |
| [`src/mcp_monitor/layers/orchestrator.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/layers/orchestrator.py) | Python layers module: orchestrator. |
| [`src/mcp_monitor/layers/proxy.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/layers/proxy.py) | Python layers module: proxy. |
| [`src/mcp_monitor/layers/semantic.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/layers/semantic.py) | Python layers module: semantic. |
| [`src/mcp_monitor/monitor.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/monitor.py) | Python monitor.py module: monitor. |
| [`src/mcp_monitor/policy/__init__.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/policy/__init__.py) | Python policy module: package exports. |
| [`src/mcp_monitor/policy/acl_guard.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/policy/acl_guard.py) | In-process ACL grants, permission revocation and authorized-search checks. |
| [`src/mcp_monitor/policy/policy_engine.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/policy/policy_engine.py) | Policy decision rules for tool permissions, server trust and egress. |
| [`src/mcp_monitor/production/__init__.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/production/__init__.py) | Python production module: package exports. |
| [`src/mcp_monitor/production/alerting.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/production/alerting.py) | Python production module: alerting. |
| [`src/mcp_monitor/production/circuit_breaker.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/production/circuit_breaker.py) | Python production module: circuit breaker. |
| [`src/mcp_monitor/production/config.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/production/config.py) | Python production module: config. |
| [`src/mcp_monitor/production/identity_shipper.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/production/identity_shipper.py) | Python production module: identity shipper. |
| [`src/mcp_monitor/production/identity_smoke.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/production/identity_smoke.py) | Python production module: identity smoke. |
| [`src/mcp_monitor/production/identity_telemetry.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/production/identity_telemetry.py) | Python production module: identity telemetry. |
| [`src/mcp_monitor/production/identity_transport.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/production/identity_transport.py) | Python production module: identity transport. |
| [`src/mcp_monitor/production/logging.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/production/logging.py) | Python production module: logging. |
| [`src/mcp_monitor/production/metrics.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/production/metrics.py) | Python production module: metrics. |
| [`src/mcp_monitor/production/rate_limiter.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/production/rate_limiter.py) | Python production module: rate limiter. |
| [`src/mcp_monitor/production/server.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/production/server.py) | Python production module: server. |
| [`src/mcp_monitor/production/shutdown.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/production/shutdown.py) | Python production module: shutdown. |
| [`src/mcp_monitor/production/tracing.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/production/tracing.py) | Python production module: tracing. |
| [`src/mcp_monitor/protocol/__init__.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/protocol/__init__.py) | Python protocol module: package exports. |
| [`src/mcp_monitor/protocol/jsonrpc.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/protocol/jsonrpc.py) | JSON-RPC parsing and protocol validation. |
| [`src/mcp_monitor/proxy/__init__.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/proxy/__init__.py) | Python proxy module: package exports. |
| [`src/mcp_monitor/proxy/stdio_proxy.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/proxy/stdio_proxy.py) | Inline stdio MCP proxy; inspects requests and downstream responses. |
| [`src/mcp_monitor/redteam/__init__.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/redteam/__init__.py) | Python redteam module: package exports. |
| [`src/mcp_monitor/redteam/payloads.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/redteam/payloads.py) | Python redteam module: payloads. |
| [`src/mcp_monitor/redteam/simulator.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/redteam/simulator.py) | Python redteam module: simulator. |
| [`src/mcp_monitor/server/__init__.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/server/__init__.py) | Python server module: package exports. |
| [`src/mcp_monitor/server/dashboard.html`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/server/dashboard.html) | Python server module: dashboard. |
| [`src/mcp_monitor/server/realtime.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/server/realtime.py) | Python server module: realtime. |
| [`src/mcp_monitor/server/workload.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/server/workload.py) | Python server module: workload. |
| [`src/mcp_monitor/siem/__init__.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/siem/__init__.py) | Python siem module: package exports. |
| [`src/mcp_monitor/siem/attack_simulations.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/siem/attack_simulations.py) | Python siem module: attack simulations. |
| [`src/mcp_monitor/siem/correlation.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/siem/correlation.py) | Python siem module: correlation. |
| [`src/mcp_monitor/siem/ecs_formatter.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/siem/ecs_formatter.py) | Python siem module: ecs formatter. |
| [`src/mcp_monitor/siem/lifecycle.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/siem/lifecycle.py) | Python siem module: lifecycle. |
| [`src/mcp_monitor/siem/shipper.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/src/mcp_monitor/siem/shipper.py) | Python siem module: shipper. |

## Tests (42)

| File (click to open) | What you will find |
|---|---|
| [`tests/__init__.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/tests/__init__.py) | Test module:   init  . |
| [`tests/test_5_layers.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/tests/test_5_layers.py) | Test module: 5 layers. |
| [`tests/test_acl_guard.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/tests/test_acl_guard.py) | Test module: acl guard. |
| [`tests/test_advanced_canary.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/tests/test_advanced_canary.py) | Test module: advanced canary. |
| [`tests/test_advanced_correlation.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/tests/test_advanced_correlation.py) | Test module: advanced correlation. |
| [`tests/test_advanced_drift.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/tests/test_advanced_drift.py) | Test module: advanced drift. |
| [`tests/test_advanced_invariants.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/tests/test_advanced_invariants.py) | Test module: advanced invariants. |
| [`tests/test_advanced_manifest.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/tests/test_advanced_manifest.py) | Test module: advanced manifest. |
| [`tests/test_alerting_security.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/tests/test_alerting_security.py) | Test module: alerting security. |
| [`tests/test_audit_log.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/tests/test_audit_log.py) | Test module: audit log. |
| [`tests/test_client.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/tests/test_client.py) | Test module: client. |
| [`tests/test_coverage_100.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/tests/test_coverage_100.py) | Test module: coverage 100. |
| [`tests/test_cross_platform.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/tests/test_cross_platform.py) | Test module: cross platform. |
| [`tests/test_defense10.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/tests/test_defense10.py) | Test module: defense10. |
| [`tests/test_deployment.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/tests/test_deployment.py) | Test module: deployment. |
| [`tests/test_detection_lifecycle.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/tests/test_detection_lifecycle.py) | Test module: detection lifecycle. |
| [`tests/test_detector_failures.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/tests/test_detector_failures.py) | Test module: detector failures. |
| [`tests/test_exfiltration.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/tests/test_exfiltration.py) | Test module: exfiltration. |
| [`tests/test_http_framing.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/tests/test_http_framing.py) | Test module: http framing. |
| [`tests/test_identity_shipper.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/tests/test_identity_shipper.py) | Test module: identity shipper. |
| [`tests/test_identity_telemetry.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/tests/test_identity_telemetry.py) | Test module: identity telemetry. |
| [`tests/test_identity_transport.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/tests/test_identity_transport.py) | Test module: identity transport. |
| [`tests/test_injection_enforcement_regression.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/tests/test_injection_enforcement_regression.py) | Test module: injection enforcement regression. |
| [`tests/test_instruction_authority_regression.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/tests/test_instruction_authority_regression.py) | Test module: instruction authority regression. |
| [`tests/test_live_filesystem_mcp.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/tests/test_live_filesystem_mcp.py) | Integration tests using a real external filesystem MCP server and disposable files. |
| [`tests/test_measure_incident_response.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/tests/test_measure_incident_response.py) | Test module: measure incident response. |
| [`tests/test_pii_detector.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/tests/test_pii_detector.py) | Test module: pii detector. |
| [`tests/test_policy_enforcement.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/tests/test_policy_enforcement.py) | Test module: policy enforcement. |
| [`tests/test_production.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/tests/test_production.py) | Test module: production. |
| [`tests/test_prompt_injection.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/tests/test_prompt_injection.py) | Test module: prompt injection. |
| [`tests/test_protocol_hardening.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/tests/test_protocol_hardening.py) | Test module: protocol hardening. |
| [`tests/test_real_mcp_protocol.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/tests/test_real_mcp_protocol.py) | Test module: real mcp protocol. |
| [`tests/test_realtime.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/tests/test_realtime.py) | Test module: realtime. |
| [`tests/test_redteam_simulator.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/tests/test_redteam_simulator.py) | Test module: redteam simulator. |
| [`tests/test_shadow_server.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/tests/test_shadow_server.py) | Test module: shadow server. |
| [`tests/test_siem.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/tests/test_siem.py) | Test module: siem. |
| [`tests/test_siem_scenarios.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/tests/test_siem_scenarios.py) | Test module: siem scenarios. |
| [`tests/test_stdio_adversarial_responses.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/tests/test_stdio_adversarial_responses.py) | Malformed and malicious downstream response tests. |
| [`tests/test_stdio_inflight_revocation.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/tests/test_stdio_inflight_revocation.py) | Controlled in-flight revocation race tests. |
| [`tests/test_stdio_policy_integration.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/tests/test_stdio_policy_integration.py) | Live stdio policy integration tests with controlled transport. |
| [`tests/test_stdio_proxy.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/tests/test_stdio_proxy.py) | Test module: stdio proxy. |
| [`tests/test_workload.py`](https://github.com/poojakira/mcp-agent-security-gateway/blob/a3359e47d68c231e20e62fb4063eb552d1c43b46/tests/test_workload.py) | Test module: workload. |

## Notes for interviews and reviewers

When asked where a control is implemented, start at `src/mcp_monitor/proxy/stdio_proxy.py`, follow the imported policy/ACL/detector/protocol modules, then open its matching `tests/` file. For audit and evidence, inspect `src/mcp_monitor/audit/`, the review docs, and the exact GitHub workflow run. Avoid describing every folder as an active runtime dependency: some folders are research modules, templates, experiments, and optional integrations.
