# MCP Security Gateway Monitor - Container Build
FROM python:3.11-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ libffi-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY tests ./tests
COPY Dockerfile docker-compose.yml locustfile.py ./
COPY deploy ./deploy

# Validate the package in the build stage; this is a build gate, not a deployment proof.
RUN pip install --no-cache-dir -e ".[dev]"
RUN pytest tests/ -v

RUN pip wheel --wheel-dir=/wheels --no-deps .

FROM python:3.11-slim AS runtime

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libffi8 libssl3 curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels

RUN groupadd -r mlsec && useradd -r -g mlsec mlsec

# Create the SIEM log directory owned by the runtime user. When the
# detection-lab compose mounts a named volume here, Docker initializes the
# empty volume from this path and preserves the mlsec ownership, so the
# non-root process can write events.ndjson for Filebeat to ship.
RUN mkdir -p /var/log/mcp-gateway && chown -R mlsec:mlsec /var/log/mcp-gateway

# Create the WAL/audit state directory owned by the runtime user. The production
# server writes MCP_WAL_PATH and MCP_AUDIT_PATH here (see docker-compose.yml,
# which mounts the mcp-state named volume at /var/lib/mcp). Docker initializes
# an empty named volume from this path and preserves the mlsec ownership, so the
# non-root process can write wal.jsonl/audit.jsonl. Without this, the volume
# mount point is created root-owned and protected requests fail with EACCES.
RUN mkdir -p /var/lib/mcp && chown -R mlsec:mlsec /var/lib/mcp

USER mlsec

# Container deployments must listen on the container interface. Local direct
# execution still defaults to 127.0.0.1 in Config.
ENV MCP_LISTEN_HOST=0.0.0.0 \
    MCP_LISTEN_PORT=8080

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/v1/health || exit 1

CMD ["python", "-c", "from mcp_monitor.production.server import run_server; run_server()"]