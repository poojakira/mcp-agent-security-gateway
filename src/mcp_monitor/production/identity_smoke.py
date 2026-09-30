"""Send exactly one live validation event from three distinct credential paths."""

from __future__ import annotations

import json
import os
import sys

from mcp_monitor.production.identity_transport import (
    load_three_credential_smoke_batch,
    post_envelope,
    redact_sensitive,
)


def main() -> int:
    endpoint = os.environ.get("MCP_IDENTITY_TELEMETRY_ENDPOINT", "").strip()
    bearer_token = os.environ.get("MCP_IDENTITY_TELEMETRY_BEARER_TOKEN", "").strip()
    tenant_salt = os.environ.get("MCP_IDENTITY_TELEMETRY_TENANT_SALT", "").strip()
    queue_path = os.environ.get("MCP_IDENTITY_TELEMETRY_OUTPUT", "").strip()

    missing = [
        name
        for name, value in (
            ("MCP_IDENTITY_TELEMETRY_ENDPOINT", endpoint),
            ("MCP_IDENTITY_TELEMETRY_BEARER_TOKEN", bearer_token),
            ("MCP_IDENTITY_TELEMETRY_TENANT_SALT", tenant_salt),
            ("MCP_IDENTITY_TELEMETRY_OUTPUT", queue_path),
        )
        if not value
    ]
    if missing:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": "missing required environment configuration",
                    "missing": missing,
                }
            )
        )
        return 2

    try:
        envelope = load_three_credential_smoke_batch(queue_path)
        result = post_envelope(
            endpoint=endpoint,
            bearer_token=bearer_token,
            envelope=envelope,
        )
    except Exception as exc:
        message = redact_sensitive(str(exc), bearer_token, tenant_salt)
        print(json.dumps({"ok": False, "error": message}))
        return 1

    sanitized_body = redact_sensitive(result.body, bearer_token, tenant_salt)
    try:
        body: object = json.loads(sanitized_body) if sanitized_body else None
    except json.JSONDecodeError:
        body = sanitized_body

    print(
        json.dumps(
            {
                "ok": 200 <= result.status < 300,
                "http_status": result.status,
                "response": body,
            },
            ensure_ascii=False,
        )
    )
    return 0 if 200 <= result.status < 300 else 1


if __name__ == "__main__":
    raise SystemExit(main())
