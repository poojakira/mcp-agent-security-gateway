"""Transport helpers for the identity-telemetry live smoke test.

The sender deliberately reads endpoint/authentication from the process
environment and never persists bearer credentials to repository files or the
telemetry queue.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcp_monitor.production.identity_telemetry import build_envelope

_DEFAULT_TIMEOUT_SECONDS = 15.0
_MAX_RESPONSE_BYTES = 64 * 1024


@dataclass(frozen=True)
class TransportResult:
    status: int
    body: str


def _load_queue_records(path: str | os.PathLike[str]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    queue_path = Path(path)
    if not queue_path.exists():
        raise ValueError(f"identity telemetry queue does not exist: {queue_path}")

    for line_number, raw_line in enumerate(
        queue_path.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        line = raw_line.strip()
        if not line:
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"invalid JSON in identity telemetry queue at line {line_number}"
            ) from exc
        if not isinstance(value, dict):
            raise ValueError(f"identity telemetry queue line {line_number} must be a JSON object")
        records.append(value)
    return records


def build_three_credential_smoke_batch(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Select one queued event from each of three distinct credential paths."""
    events: list[dict[str, Any]] = []
    event_fps: list[str] = []
    seen_key_fps: set[str] = set()

    for record in records:
        record_events = record.get("events")
        record_fps = record.get("event_fps")
        if not isinstance(record_events, list) or not isinstance(record_fps, list):
            raise ValueError("queued record must contain events and event_fps arrays")
        if len(record_events) != len(record_fps):
            raise ValueError("queued record events/event_fps lengths do not match")

        for event, event_fp in zip(record_events, record_fps, strict=True):
            if not isinstance(event, dict):
                raise ValueError("queued event must be an object")
            key_fp = event.get("key_fp")
            if not isinstance(key_fp, str) or len(key_fp) != 32:
                raise ValueError("queued event key_fp must be a 32-character string")
            if key_fp in seen_key_fps:
                continue

            seen_key_fps.add(key_fp)
            events.append(event)
            event_fps.append(event_fp)

            if len(events) == 3:
                return build_envelope(events, event_fps)

    raise ValueError("smoke test requires queued events from three distinct credential paths")


def load_three_credential_smoke_batch(
    queue_path: str | os.PathLike[str],
) -> dict[str, Any]:
    return build_three_credential_smoke_batch(_load_queue_records(queue_path))


def post_envelope(
    *,
    endpoint: str,
    bearer_token: str,
    envelope: dict[str, Any],
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
) -> TransportResult:
    """POST one JSON envelope using bearer authentication."""
    if not endpoint.startswith("https://"):
        raise ValueError("identity telemetry endpoint must use HTTPS")
    if not bearer_token:
        raise ValueError("bearer token must not be empty")

    payload = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        endpoint,
        data=payload,
        method="POST",
        headers={
            "Authorization": f"Bearer {bearer_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "mcp-gateway/1.0.0",
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            raw = response.read(_MAX_RESPONSE_BYTES)
            return TransportResult(
                status=int(response.status),
                body=raw.decode("utf-8", errors="replace"),
            )
    except urllib.error.HTTPError as exc:
        raw = exc.read(_MAX_RESPONSE_BYTES)
        return TransportResult(
            status=int(exc.code),
            body=raw.decode("utf-8", errors="replace"),
        )


def redact_sensitive(text: str, *sensitive_values: str) -> str:
    redacted = text
    for value in sensitive_values:
        if value:
            redacted = redacted.replace(value, "<redacted>")
    return redacted
