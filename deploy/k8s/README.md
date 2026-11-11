> **Evidence reconciliation (2026-11-11; living reference):** Historical results below retain their original dates and denominators. Latest tested Phase 1–16 development SHA is `43a72c8984bf9a472b9055d4f9e84cc759f61718` ([CI](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/42971171992): 1,211 passed, 6 skipped per Python version), **not** a merged or production-approved release. Offline research tests require no paid provider or provider-issued API keys; deployed HTTP authentication and unverified real credential revocation remain separate. See [operating restrictions](../../PRODUCTION.md) and [release evidence](../../docs/review/PHASE1_16_RELEASE_CANDIDATE_NO_GO_20261110.md).

# Kubernetes Deployment

> **Evidence and release status (2026-11-09):** These manifests are deployment examples, not approved Kubernetes hardening. An in-cluster network policy, real identity boundary, durable state and tested failure/rollback path must be verified in the actual cluster before production. The [release review](../../docs/review/PHASE13_RELEASE_READINESS.md) remains **NO-GO**, and [PR #167](https://github.com/poojakira/mcp-agent-security-gateway/pull/167) is a draft integration candidate.
This directory contains a conservative single-replica deployment for the MCP
Security Gateway.

## Before applying

The sample ConfigMap runs the service under `MCP_ENV=production`, binds on
`0.0.0.0:8080`, disables anonymous access, and writes audit/WAL state to the
PVC. Replace the example `MCP_ALLOWED_SERVERS=github` with the exact server IDs
approved for your environment.

Create the API credential Secret. The sample keeps the legacy single-key path; production environments may instead provide `MCP_API_KEYS` with multiple stable credentials:

```bash
kubectl apply -f deploy/k8s/namespace.yaml
MCP_API_KEY="$(openssl rand -hex 32)"
kubectl create secret generic mcp-monitor-secrets \
  --namespace mcp-monitor \
  --from-literal=MCP_API_KEY="$MCP_API_KEY"
```

`secret.example.yaml` is documentation-only and intentionally not an
applyable Secret.

## Image

The sample Deployment references the repository release image. For controlled
production promotion, replace the tag with an **immutable digest**, for example:

```yaml
image: ghcr.io/poojakira/mcp-agent-security-gateway@sha256:<digest>
```

Do not deploy a locally mutable `:latest` tag.

## Apply

```bash
kubectl apply -f deploy/k8s/configmap.yaml
kubectl apply -f deploy/k8s/pvc.yaml
kubectl apply -f deploy/k8s/deployment.yaml
kubectl apply -f deploy/k8s/service.yaml
kubectl apply -f deploy/k8s/hpa.yaml
```

## Durability and scaling

The sample uses one replica and a `ReadWriteOnce` PVC because the local WAL
and audit files are single-writer state. The HPA is deliberately capped at one
replica. Do not increase replicas against the same file-backed paths. Move
audit/WAL persistence to an external concurrency-safe backend or give each pod
its own durable volume before horizontal scaling.

## Verify

```bash
kubectl get pods -n mcp-monitor
kubectl logs -n mcp-monitor deploy/mcp-monitor
kubectl port-forward -n mcp-monitor svc/mcp-monitor 8080:80
curl http://127.0.0.1:8080/v1/health
curl http://127.0.0.1:8080/v1/ready
curl -H "X-API-Key: $MCP_API_KEY" http://127.0.0.1:8080/v1/metrics
```

The health and readiness endpoints are intentionally unauthenticated for orchestration. Runtime metrics and inspection endpoints require a configured service credential.

When deploying behind an ingress or load balancer, do not trust client-supplied `X-Forwarded-For` by default. Configure `MCP_TRUSTED_PROXY_CIDRS` only for infrastructure you control and that overwrites/sanitizes forwarded source headers. The gateway otherwise uses the socket peer address.

Optional external-validation transport output also requires `MCP_IDENTITY_TELEMETRY_TENANT_SALT` and `MCP_IDENTITY_TELEMETRY_OUTPUT`. Keep the tenant salt in a Kubernetes Secret and mount the output on durable storage if you enable the local queue. Each NDJSON line is an immutable envelope with `schema_version: 1`, client `mcp-gateway/1.0.0`, `backfill: false`, an `events` array, and a positional `event_fps` array. Raw API credentials, raw source addresses, and internal event IDs are not written to the transport envelope.

## Production gate

Do not apply these example manifests to production without trusted workload identity, authorization, network ingress/egress isolation, persistent audit/effect state, image/SBOM review, tested rollback and explicit approval. Passing example syntax or smoke checks alone does not close these requirements.
