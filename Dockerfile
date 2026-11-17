# MCP Security Gateway Monitor - Container Build
ARG PYTHON_BASE_IMAGE=python:3.11-slim@sha256:07d4824036af339fa1b6ef769cc99d9c10a141769538b52b3b597c84f7a7b535
FROM ${PYTHON_BASE_IMAGE} AS builder

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY tests ./tests
COPY benchmark ./benchmark
# This source-only measurement helper is imported by a builder-stage regression test.
# It is intentionally not copied into the runtime stage.
COPY scripts ./scripts
COPY docs ./docs
COPY policy ./policy
COPY .github/workflows ./.github/workflows
COPY *.md ./
COPY detection_rules ./detection_rules
COPY Dockerfile docker-compose.yml docker-compose.detection-lab.yml locustfile.py ./
COPY deploy ./deploy

# Validate the package in the build stage; this is a build gate, not a deployment proof.
# Optional operator CA is scoped to package installation in the builder only.
# Never disable certificate verification for an intercepting build proxy.
RUN --mount=type=secret,id=pip_ca \
    if [ -f /run/secrets/pip_ca ]; then export PIP_CERT=/run/secrets/pip_ca; fi; \
    pip install --no-cache-dir -e ".[dev,oidc]" \
    && python -m pytest tests/ -q \
    && pip wheel --wheel-dir=/wheels .

# Runtime contains only the pure-Python application wheel. Keep the
# Debian build/test stage separate from the minimal musl runtime to reduce
# the vulnerable runtime OS package footprint.
# Release CI supplies python:3.11-alpine@sha256:<resolved-index-digest>.
# The tag default is for developer builds, never a production release pin.
ARG PYTHON_RUNTIME_IMAGE=python:3.11-alpine
FROM ${PYTHON_RUNTIME_IMAGE} AS runtime

WORKDIR /app

RUN apk upgrade --no-cache

COPY --from=builder /wheels /wheels
COPY --from=builder --chmod=0555 /app/detection_rules /app/detection_rules
RUN pip install --no-index --no-cache-dir /wheels/*.whl \
    && python -m pip uninstall -y pip setuptools \
    && python -c "import pathlib, shutil, sysconfig; shutil.rmtree(pathlib.Path(sysconfig.get_path('stdlib')) / 'ensurepip')" \
    && rm -rf /wheels

RUN addgroup -S mlsec && adduser -S -G mlsec mlsec

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
    MCP_LISTEN_PORT=8080 \
    MCP_ELASTIC_RULES_PATH=/app/detection_rules/elastic_rules.toml

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.build_opener(urllib.request.ProxyHandler({})).open('http://127.0.0.1:8080/v1/health', timeout=5).close()"

CMD ["python", "-c", "from mcp_monitor.production.server import run_server; run_server()"]