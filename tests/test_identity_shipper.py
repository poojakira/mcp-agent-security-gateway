"""Tests for durable identity telemetry delivery."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from mcp_monitor.production.identity_shipper import deliver_available
from mcp_monitor.production.identity_transport import TransportResult


def _envelope(event_fp: str) -> dict:
    return {
        "schema_version": 1,
        "client": "mcp-gateway/1.0.0",
        "backfill": False,
        "events": [{"key_fp": "a" * 32}],
        "event_fps": [event_fp],
    }


def _write_queue(path: Path, *records: dict) -> None:
    path.write_text(
        "".join(json.dumps(record, separators=(",", ":")) + "\n" for record in records),
        encoding="utf-8",
    )


def test_deliver_available_advances_cursor_after_success(tmp_path: Path) -> None:
    queue = tmp_path / "queue.ndjson"
    cursor = tmp_path / "queue.cursor"
    _write_queue(queue, _envelope("1" * 32), _envelope("2" * 32))

    with patch(
        "mcp_monitor.production.identity_shipper.post_envelope",
        return_value=TransportResult(status=202, body='{"accepted":1}'),
    ) as post:
        delivered = deliver_available(
            queue_path=queue,
            cursor_path=cursor,
            endpoint="https://example.invalid/v1/events",
            bearer_token="runtime-secret",
        )

    assert delivered == 2
    assert post.call_count == 2
    assert int(cursor.read_text(encoding="utf-8").strip()) == queue.stat().st_size


def test_failed_delivery_does_not_advance_cursor(tmp_path: Path) -> None:
    queue = tmp_path / "queue.ndjson"
    cursor = tmp_path / "queue.cursor"
    _write_queue(queue, _envelope("1" * 32))

    with patch(
        "mcp_monitor.production.identity_shipper.post_envelope",
        return_value=TransportResult(status=503, body='{"error":"unavailable"}'),
    ):
        delivered = deliver_available(
            queue_path=queue,
            cursor_path=cursor,
            endpoint="https://example.invalid/v1/events",
            bearer_token="runtime-secret",
        )

    assert delivered == 0
    assert not cursor.exists()


def test_retry_resends_same_immutable_envelope(tmp_path: Path) -> None:
    queue = tmp_path / "queue.ndjson"
    cursor = tmp_path / "queue.cursor"
    record = _envelope("f" * 32)
    _write_queue(queue, record)

    responses = [
        TransportResult(status=500, body="failed"),
        TransportResult(status=202, body='{"accepted":1}'),
    ]
    captured: list[dict] = []

    def fake_post(**kwargs):
        captured.append(kwargs["envelope"])
        return responses.pop(0)

    with patch("mcp_monitor.production.identity_shipper.post_envelope", side_effect=fake_post):
        first = deliver_available(
            queue_path=queue,
            cursor_path=cursor,
            endpoint="https://example.invalid/v1/events",
            bearer_token="runtime-secret",
        )
        second = deliver_available(
            queue_path=queue,
            cursor_path=cursor,
            endpoint="https://example.invalid/v1/events",
            bearer_token="runtime-secret",
        )

    assert first == 0
    assert second == 1
    assert captured == [record, record]
    assert int(cursor.read_text(encoding="utf-8").strip()) == queue.stat().st_size


def test_partial_queue_record_is_not_sent(tmp_path: Path) -> None:
    queue = tmp_path / "queue.ndjson"
    cursor = tmp_path / "queue.cursor"
    queue.write_text(json.dumps(_envelope("1" * 32)), encoding="utf-8")

    with patch("mcp_monitor.production.identity_shipper.post_envelope") as post:
        delivered = deliver_available(
            queue_path=queue,
            cursor_path=cursor,
            endpoint="https://example.invalid/v1/events",
            bearer_token="runtime-secret",
        )

    assert delivered == 0
    post.assert_not_called()
    assert not cursor.exists()


def test_missing_queue_is_idle_not_failure(tmp_path: Path) -> None:
    delivered = deliver_available(
        queue_path=tmp_path / "missing.ndjson",
        cursor_path=tmp_path / "queue.cursor",
        endpoint="https://example.invalid/v1/events",
        bearer_token="runtime-secret",
    )
    assert delivered == 0
