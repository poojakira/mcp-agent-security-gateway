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
USER mlsec

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/v1/health || exit 1

CMD ["python", "-c", "from mcp_monitor.production.server import run_server; run_server()"]