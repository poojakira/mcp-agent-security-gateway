"""Durable queue-to-HTTPS delivery worker for identity telemetry.

The gateway writes immutable NDJSON envelopes to a local queue. This worker
ships complete queue records in order and advances a durable byte-offset
checkpoint only after a successful 2xx response. If delivery is ambiguous or
fails, the checkpoint is not advanced, so the same immutable envelope is
retried and the receiver can deduplicate it by event_fps.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

from mcp_monitor.production.identity_transport import post_envelope, redact_sensitive

_DEFAULT_POLL_SECONDS = 2.0
_DEFAULT_MAX_BACKOFF_SECONDS = 60.0


def _read_cursor(path: str | os.PathLike[str]) -> int:
    cursor_path = Path(path)
    if not cursor_path.exists():
        return 0
    raw = cursor_path.read_text(encoding="utf-8").strip()
    if not raw:
        return 0
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError("identity telemetry cursor is not an integer") from exc
    if value < 0:
        raise ValueError("identity telemetry cursor must be non-negative")
    return value


def _write_cursor(path: str | os.PathLike[str], offset: int) -> None:
    if offset < 0:
        raise ValueError("identity telemetry cursor must be non-negative")
    cursor_path = Path(path)
    cursor_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = cursor_path.with_name(cursor_path.name + ".tmp")
    with tmp_path.open("w", encoding="utf-8") as fh:
        fh.write(str(offset) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp_path, cursor_path)
    # Persist the rename itself on POSIX filesystems. Opening directories for
    # fsync is not portable to Windows, where os.replace already provides the
    # atomic replacement used by this worker.
    if os.name != "nt":
        dir_fd = os.open(cursor_path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)


def _read_next_envelope(
    queue_path: str | os.PathLike[str],
    offset: int,
) -> tuple[dict[str, Any], int] | None:
    path = Path(queue_path)
    if not path.exists():
        return None

    size = path.stat().st_size
    if offset > size:
        raise ValueError("identity telemetry queue is smaller than the persisted cursor")

    with path.open("rb") as fh:
        fh.seek(offset)
        raw = fh.readline()
        if not raw:
            return None
        # The gateway appends one newline-terminated envelope per request.
        # Never send a partially written record.
        if not raw.endswith(b"\n"):
            return None
        next_offset = fh.tell()

    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid identity telemetry queue record") from exc
    if not isinstance(value, dict):
        raise ValueError("identity telemetry queue record must be a JSON object")
    return value, next_offset


def deliver_available(
    *,
    queue_path: str | os.PathLike[str],
    cursor_path: str | os.PathLike[str],
    endpoint: str,
    bearer_token: str,
    max_records: int | None = None,
) -> int:
    """Deliver queued envelopes in order until empty or the first failed POST."""
    if max_records is not None and max_records <= 0:
        raise ValueError("max_records must be positive")

    delivered = 0
    offset = _read_cursor(cursor_path)

    while max_records is None or delivered < max_records:
        item = _read_next_envelope(queue_path, offset)
        if item is None:
            break

        envelope, next_offset = item
        result = post_envelope(
            endpoint=endpoint,
            bearer_token=bearer_token,
            envelope=envelope,
        )
        if not 200 <= result.status < 300:
            raise RuntimeError(
                f"identity telemetry endpoint returned HTTP {result.status}"
            )

        _write_cursor(cursor_path, next_offset)
        offset = next_offset
        delivered += 1

    return delivered


def _required_environment() -> tuple[str, str, str, str]:
    endpoint = os.environ.get("MCP_IDENTITY_TELEMETRY_ENDPOINT", "").strip()
    bearer_token = os.environ.get("MCP_IDENTITY_TELEMETRY_BEARER_TOKEN", "").strip()
    queue_path = os.environ.get("MCP_IDENTITY_TELEMETRY_OUTPUT", "").strip()
    cursor_path = os.environ.get("MCP_IDENTITY_TELEMETRY_CURSOR", "").strip()

    missing = [
        name
        for name, value in (
            ("MCP_IDENTITY_TELEMETRY_ENDPOINT", endpoint),
            ("MCP_IDENTITY_TELEMETRY_BEARER_TOKEN", bearer_token),
            ("MCP_IDENTITY_TELEMETRY_OUTPUT", queue_path),
            ("MCP_IDENTITY_TELEMETRY_CURSOR", cursor_path),
        )
        if not value
    ]
    if missing:
        raise ValueError("missing required environment configuration: " + ",".join(missing))
    return endpoint, bearer_token, queue_path, cursor_path


def run_forever() -> None:
    endpoint, bearer_token, queue_path, cursor_path = _required_environment()
    poll_seconds = max(
        0.1,
        float(os.environ.get("MCP_IDENTITY_TELEMETRY_POLL_SECONDS", _DEFAULT_POLL_SECONDS)),
    )
    max_backoff = max(
        poll_seconds,
        float(
            os.environ.get(
                "MCP_IDENTITY_TELEMETRY_MAX_BACKOFF_SECONDS",
                _DEFAULT_MAX_BACKOFF_SECONDS,
            )
        ),
    )

    backoff = poll_seconds
    while True:
        try:
            delivered = deliver_available(
                queue_path=queue_path,
                cursor_path=cursor_path,
                endpoint=endpoint,
                bearer_token=bearer_token,
            )
            if delivered:
                print(json.dumps({"identity_telemetry_delivered": delivered}), flush=True)
                backoff = poll_seconds
                continue
            time.sleep(poll_seconds)
            backoff = poll_seconds
        except Exception as exc:
            # Never expose the bearer token through exception text.
            safe = redact_sensitive(str(exc), bearer_token)
            print(json.dumps({"identity_telemetry_delivery_error": safe}), flush=True)
            time.sleep(backoff)
            backoff = min(max_backoff, max(poll_seconds, backoff * 2))


def main() -> int:
    try:
        run_forever()
    except KeyboardInterrupt:
        return 0
    except Exception as exc:
        bearer_token = os.environ.get("MCP_IDENTITY_TELEMETRY_BEARER_TOKEN", "")
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": redact_sensitive(str(exc), bearer_token),
                }
            ),
            flush=True,
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
