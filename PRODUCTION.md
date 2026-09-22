# Production Operating Contract

## System role

This repository is maintained as a **MCP/JSON-RPC security gateway**.

## Production purpose

inspect and enforce agent-to-tool policy decisions across supported integration paths.

## Release gate

A release is promotable only when tests, lint/type checks, SAST, dependency audit, container/security scans, and deployment smoke checks pass.

## Operating requirements

- Configuration must come from explicit environment/config files; secrets must never be committed.
- Production defaults must fail safely when required identity, credentials, artifacts, or dependencies are missing.
- Health/readiness behavior must represent real dependency state where the repository exposes a service.
- Logs and machine-readable outputs must support incident/debug reconstruction without leaking secrets.
- Dependency and security findings at the repository's blocking threshold must stop promotion.
- Public metrics and benchmark claims must identify their dataset, environment, and scope.
- Deployment images/artifacts must be versioned and immutable at promotion time.
- Rollback must be possible without rewriting Git history.

## Evidence boundary

"Production-oriented" describes the engineering and release contract of this repository. It does **not** mean that an external enterprise deployment, penetration test, certification, uptime history, or scale target has occurred unless a separate committed artifact proves it.

## Change management

Main is the supported integration branch. Production changes should be small, reviewable, tested, and tied to observable behavior. Historical benchmark/research material may remain for evidence, but active README, security, runbook, and deployment surfaces must describe the supported runtime rather than an academic or prototype status.
