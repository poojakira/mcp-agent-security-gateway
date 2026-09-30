"""Tests for identity telemetry smoke transport."""

from __future__ import annotations

import json
import os
from unittest.mock import patch

import pytest

from mcp_monitor.production import identity_smoke
from mcp_monitor.production.identity_transport import (
    TransportResult,
    build_three_credential_smoke_batch,
    post_envelope,
    redact_sensitive,
)


def _record(key_fp: str, event_fp: str, endpoint: str) -> dict:
    return {
        "schema_version": 1,
        "client": "mcp-gateway/1.0.0",
        "backfill": False,
        "events": [
            {
                "ts": "2026-09-30T01:00:00.000Z",
                "key_fp": key_fp,
                "endpoint": endpoint,
                "tokens_in": 0,
                "tokens_out": 0,
                "latency_ms": 10,
                "status": 200,
                "ip_fp": "1" * 32,
                "ip_net_fp": "2" * 32,
                "ip_block_fp": "3" * 32,
                "ip_family": "v4",
                "cost": None,
            }
        ],
        "event_fps": [event_fp],
    }


def test_smoke_batch_selects_three_distinct_credentials() -> None:
    records = [
        _record("a" * 32, "1" * 32, "/v1/inspect_call"),
        _record("a" * 32, "2" * 32, "/v1/inspect_output"),
        _record("b" * 32, "3" * 32, "/v1/inspect_call"),
        _record("c" * 32, "4" * 32, "/v1/inspect_output"),
    ]
    batch = build_three_credential_smoke_batch(records)

    assert batch["schema_version"] == 1
    assert batch["client"] == "mcp-gateway/1.0.0"
    assert batch["backfill"] is False
    assert [event["key_fp"] for event in batch["events"]] == [
        "a" * 32,
        "b" * 32,
        "c" * 32,
    ]
    assert batch["event_fps"] == ["1" * 32, "3" * 32, "4" * 32]


def test_smoke_batch_requires_three_distinct_credentials() -> None:
    with pytest.raises(ValueError, match="three distinct credential paths"):
        build_three_credential_smoke_batch(
            [
                _record("a" * 32, "1" * 32, "/v1/inspect_call"),
                _record("b" * 32, "2" * 32, "/v1/inspect_output"),
            ]
        )


def test_post_envelope_uses_bearer_auth_and_single_post() -> None:
    class Response:
        status = 202

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _limit):
            return b'{"accepted":3}'

    captured = {}

    def fake_urlopen(request, timeout):
        captured["request"] = request
        captured["timeout"] = timeout
        return Response()

    envelope = {
        "schema_version": 1,
        "client": "mcp-gateway/1.0.0",
        "backfill": False,
        "events": [{"key_fp": "a" * 32}],
        "event_fps": ["1" * 32],
    }

    with patch("urllib.request.urlopen", side_effect=fake_urlopen) as mocked:
        result = post_envelope(
            endpoint="https://example.invalid/v1/events",
            bearer_token="secret-token",
            envelope=envelope,
        )

    assert mocked.call_count == 1
    assert result.status == 202
    assert json.loads(result.body) == {"accepted": 3}
    request = captured["request"]
    assert request.get_method() == "POST"
    assert request.get_header("Authorization") == "Bearer secret-token"
    assert request.get_header("Content-type") == "application/json"
    assert json.loads(request.data.decode("utf-8")) == envelope


def test_post_envelope_rejects_non_https_endpoint() -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        post_envelope(
            endpoint="http://example.invalid/v1/events",
            bearer_token="secret-token",
            envelope={},
        )


def test_redact_sensitive_removes_secret_values() -> None:
    text = "token=secret-token salt=secret-salt"
    redacted = redact_sensitive(text, "secret-token", "secret-salt")
    assert "secret-token" not in redacted
    assert "secret-salt" not in redacted
    assert redacted == "token=<redacted> salt=<redacted>"



def test_smoke_cli_reports_missing_runtime_configuration(capsys) -> None:
    with patch.dict(os.environ, {}, clear=True):
        assert identity_smoke.main() == 2

    output = json.loads(capsys.readouterr().out)
    assert output["ok"] is False
    assert set(output["missing"]) == {
        "MCP_IDENTITY_TELEMETRY_ENDPOINT",
        "MCP_IDENTITY_TELEMETRY_BEARER_TOKEN",
        "MCP_IDENTITY_TELEMETRY_TENANT_SALT",
        "MCP_IDENTITY_TELEMETRY_OUTPUT",
    }


def test_smoke_cli_prints_redacted_success_output(capsys) -> None:
    env = {
        "MCP_IDENTITY_TELEMETRY_ENDPOINT": "https://example.invalid/v1/events",
        "MCP_IDENTITY_TELEMETRY_BEARER_TOKEN": "runtime-secret-token",
        "MCP_IDENTITY_TELEMETRY_TENANT_SALT": "runtime-secret-salt",
        "MCP_IDENTITY_TELEMETRY_OUTPUT": "/tmp/identity-telemetry.ndjson",
    }
    envelope = {
        "schema_version": 1,
        "client": "mcp-gateway/1.0.0",
        "backfill": False,
        "events": [{"key_fp": "a" * 32}],
        "event_fps": ["1" * 32],
    }
    response = '{"accepted":3,"note":"runtime-secret-token runtime-secret-salt"}'

    with (
        patch.dict(os.environ, env, clear=True),
        patch.object(identity_smoke, "load_three_credential_smoke_batch", return_value=envelope),
        patch.object(
            identity_smoke,
            "post_envelope",
            return_value=TransportResult(status=202, body=response),
        ),
    ):
        assert identity_smoke.main() == 0

    raw_output = capsys.readouterr().out
    assert "runtime-secret-token" not in raw_output
    assert "runtime-secret-salt" not in raw_output
    output = json.loads(raw_output)
    assert output["ok"] is True
    assert output["http_status"] == 202
    assert output["response"]["accepted"] == 3
    assert output["response"]["note"] == "<redacted> <redacted>"


def test_smoke_cli_redacts_exception_text(capsys) -> None:
    env = {
        "MCP_IDENTITY_TELEMETRY_ENDPOINT": "https://example.invalid/v1/events",
        "MCP_IDENTITY_TELEMETRY_BEARER_TOKEN": "runtime-secret-token",
        "MCP_IDENTITY_TELEMETRY_TENANT_SALT": "runtime-secret-salt",
        "MCP_IDENTITY_TELEMETRY_OUTPUT": "/tmp/identity-telemetry.ndjson",
    }

    with (
        patch.dict(os.environ, env, clear=True),
        patch.object(
            identity_smoke,
            "load_three_credential_smoke_batch",
            side_effect=ValueError("runtime-secret-token runtime-secret-salt"),
        ),
    ):
        assert identity_smoke.main() == 1

    raw_output = capsys.readouterr().out
    assert "runtime-secret-token" not in raw_output
    assert "runtime-secret-salt" not in raw_output
    output = json.loads(raw_output)
    assert output["ok"] is False
    assert output["error"] == "<redacted> <redacted>"
