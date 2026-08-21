# RUNBOOK  --  MCP Agent Security Gateway

## Prerequisites

- Python 3.11+
- Docker (for container deployment)
- kubectl + cluster access (for K8s deployment)
- pip or uv package manager

## Install from Source

```bash
git clone <repo-url> && cd mcp-agent-security-gateway
python -m venv .venv && source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Run Tests

```bash
pytest tests/ -v
pytest tests/ -v --cov=src --cov-report=term-missing
```

## Run the Gateway

```bash
# Start the gateway server (entry point from pyproject.toml)
mcp-gateway

# Or run directly via module
python -m mcp_monitor.production.server

# Environment overrides
export MCP_GATEWAY_LOG_LEVEL=debug
```

## Docker Deployment

```bash
docker build -t mcp-security-gateway:latest .
docker run -d --name mcp-gw \
  -p 8080:8080 \
  -v $(pwd)/config.yaml:/app/config.yaml:ro \
  mcp-security-gateway:latest

# Health check
curl http://localhost:8080/health
```

## K8s Deployment

```bash
kubectl apply -f deploy/k8s/namespace.yaml
kubectl apply -f deploy/k8s/deployment.yaml
kubectl apply -f deploy/k8s/service.yaml

# Verify
kubectl -n mcp-gateway get pods
kubectl -n mcp-gateway logs -l app=mcp-gateway --tail=50
```

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Gateway rejects all calls | Policy file missing or malformed | Validate YAML: `python -m mcp_gateway.validate_config config.yaml` |
| Connection refused on 8080 | Port conflict or not started | Check `netstat -tlnp | grep 8080`, verify container is running |
| High latency on inspection | Large payloads + regex rules | Reduce regex complexity, increase worker count |
| K8s CrashLoopBackOff | Missing configmap or secrets | Check `kubectl describe pod <pod>`, verify mounts |
| Stdio passthrough hangs | Upstream MCP server unresponsive | Check upstream health, add timeout in config |
