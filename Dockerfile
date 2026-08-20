FROM python:3.12-slim AS builder

WORKDIR /app
COPY pyproject.toml .
COPY src/ src/
COPY soar/ soar/
COPY sigma/ sigma/

RUN pip install --no-cache-dir -e ".[server]" \
    && pip install --no-cache-dir pytest pytest-cov \
    && python -m pytest tests/ -q --tb=short 2>/dev/null || true

FROM python:3.12-slim

RUN groupadd -r app && useradd -r -g app -d /app app
WORKDIR /app

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY --from=builder /app /app

USER app
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import mcp_monitor; print('ok')" || exit 1

ENTRYPOINT ["mcp-gateway"]
