"""Reject ambiguous or invalid JSON before entering inspection handlers."""

from __future__ import annotations

import json

import pytest

from mcp_monitor.production.server import ProductionServer


@pytest.mark.parametrize(
    "payload",
    [
        b'{"name":"read_file","name":"write_file","server_id":"filesystem"}',
        b'{"arguments":{"path":"safe","path":"restricted"}}',
        b'{"risk":NaN}',
        b'{"risk":Infinity}',
        b'{"risk":-Infinity}',
        b'[]',
        b'null',
        b'"string"',
        b'42',
    ],
)
def test_inspection_parser_rejects_ambiguous_and_non_object_input(payload: bytes) -> None:
    with pytest.raises((ValueError, json.JSONDecodeError)):
        ProductionServer._parse_inspection_json(payload)


@pytest.mark.parametrize("payload", [b'{}', b'{"name":"read_file","arguments":{}}'])
def test_inspection_parser_accepts_json_objects(payload: bytes) -> None:
    assert ProductionServer._parse_inspection_json(payload) == json.loads(payload)


@pytest.mark.parametrize(
    "handler",
    ["_handle_inspect_call", "_handle_inspect_output"],
)
@pytest.mark.parametrize(
    "payload",
    [
        b'{"name":"read_file","name":"write_file"}',
        b'{"arguments":{"path":"a","path":"b"}}',
        b'{"arguments":{"amount":NaN}}',
        b'[]',
        b'null',
    ],
)
def test_inspection_endpoints_reject_invalid_json_before_execution(
    handler: str, payload: bytes
) -> None:
    # Bypass initialization to verify only the input-validation boundary.
    server = object.__new__(ProductionServer)
    status, result = getattr(server, handler)(payload, "trace", "span")
    assert status == 400
    assert "Invalid JSON" in result["error"]
