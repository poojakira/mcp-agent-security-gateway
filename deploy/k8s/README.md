# Kubernetes Deployment

This directory contains a conservative single-replica deployment for the MCP
Security Gateway.

## Before applying

The sample ConfigMap runs the service under `MCP_ENV=production`, binds on
`0.0.0.0:8080`, disables anonymous access, and writes audit/WAL state to the
PVC. Replace the example `MCP_ALLOWED_SERVERS=github` with the exact server IDs
approved for your environment.

Create the API key Secret:

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

The health and readiness endpoints are intentionally unauthenticated for
orchestration. Runtime metrics and inspection endpoints require the service key.
