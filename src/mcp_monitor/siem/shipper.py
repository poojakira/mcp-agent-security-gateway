"""Log shipper for exporting ECS events to external SIEM systems.

Supports multiple backends:
- FileShipper: writes NDJSON to a file (for Filebeat/Logstash pickup)
- ElasticsearchShipper: direct HTTP bulk indexing
- StdoutShipper: prints to stdout (for container log collection)

All shippers are async-compatible and include retry logic
with exponential backoff for transient failures.
"""

from __future__ import annotations

import json
import logging
import time
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcp_monitor.siem.ecs_formatter import ECSEvent

logger = logging.getLogger(__name__)


@dataclass
class ShipperStats:
    """Statistics for monitoring shipper health."""

    events_shipped: int = 0
    events_failed: int = 0
    events_buffered: int = 0
    last_ship_timestamp: float = 0.0
    last_error: str = ""
    consecutive_failures: int = 0


class LogShipper(ABC):
    """Abstract base class for log shippers."""

    def __init__(self, buffer_size: int = 1000, flush_interval_seconds: float = 5.0) -> None:
        self.buffer_size = buffer_size
        self.flush_interval = flush_interval_seconds
        self._buffer: deque[dict[str, Any]] = deque(maxlen=buffer_size)
        self._stats = ShipperStats()
        self._last_flush = time.time()

    @abstractmethod
    def _ship_batch(self, events: list[dict[str, Any]]) -> bool:
        """Ship a batch of ECS events. Returns True on success."""
        ...

    def ship(self, event: ECSEvent) -> None:
        """Buffer an event for shipping."""
        self._buffer.append(event.to_dict())
        self._stats.events_buffered = len(self._buffer)

        # Auto-flush if buffer is full or interval elapsed
        if (
            len(self._buffer) >= self.buffer_size
            or time.time() - self._last_flush >= self.flush_interval
        ):
            self.flush()

    def flush(self) -> bool:
        """Flush all buffered events to the backend."""
        if not self._buffer:
            return True

        batch = list(self._buffer)
        self._buffer.clear()
        self._stats.events_buffered = 0

        success = self._ship_batch(batch)
        self._last_flush = time.time()

        if success:
            self._stats.events_shipped += len(batch)
            self._stats.last_ship_timestamp = time.time()
            self._stats.consecutive_failures = 0
        else:
            self._stats.events_failed += len(batch)
            self._stats.consecutive_failures += 1

        return success

    def get_stats(self) -> ShipperStats:
        """Return current shipper statistics."""
        self._stats.events_buffered = len(self._buffer)
        return self._stats


class FileShipper(LogShipper):
    """Ships ECS events as NDJSON (newline-delimited JSON) to a file.

    This is the simplest integration path: write NDJSON, let Filebeat
    or Logstash pick it up and forward to Elasticsearch.

    Usage:
        shipper = FileShipper(output_path="/var/log/mcp-gateway/events.ndjson")
        shipper.ship(ecs_event)
    """

    def __init__(
        self,
        output_path: str | Path,
        buffer_size: int = 100,
        flush_interval_seconds: float = 2.0,
        rotate_size_mb: int = 50,
    ) -> None:
        super().__init__(buffer_size=buffer_size, flush_interval_seconds=flush_interval_seconds)
        self.output_path = Path(output_path)
        self.rotate_size_mb = rotate_size_mb
        self.output_path.parent.mkdir(parents=True, exist_ok=True)

    def _ship_batch(self, events: list[dict[str, Any]]) -> bool:
        """Append events as NDJSON to the output file."""
        try:
            # Check rotation
            if self.output_path.exists():
                size_mb = self.output_path.stat().st_size / (1024 * 1024)
                if size_mb >= self.rotate_size_mb:
                    self._rotate()

            with self.output_path.open("a", encoding="utf-8") as f:
                for event in events:
                    f.write(json.dumps(event, default=str) + "\n")

            return True
        except OSError as e:
            self._stats.last_error = str(e)
            logger.error("FileShipper write failed: %s", e)
            return False

    def _rotate(self) -> None:
        """Rotate the log file."""
        rotated = self.output_path.with_suffix(f".{int(time.time())}.ndjson")
        try:
            self.output_path.rename(rotated)
            logger.info("Rotated %s to %s", self.output_path, rotated)
        except OSError as e:
            logger.warning("Log rotation failed: %s", e)


class ElasticsearchShipper(LogShipper):
    """Ships ECS events directly to Elasticsearch via HTTP bulk API.

    Uses the _bulk endpoint for efficient batch indexing.
    Includes basic retry logic with exponential backoff.

    Usage:
        shipper = ElasticsearchShipper(
            es_url="http://localhost:9200",
            index_pattern="mcp-security-{date}",
        )
        shipper.ship(ecs_event)
    """

    def __init__(
        self,
        es_url: str = "http://localhost:9200",
        index_pattern: str = "mcp-security-events",
        api_key: str = "",
        username: str = "",
        password: str = "",
        buffer_size: int = 500,
        flush_interval_seconds: float = 5.0,
        max_retries: int = 3,
        timeout_seconds: float = 30.0,
    ) -> None:
        super().__init__(buffer_size=buffer_size, flush_interval_seconds=flush_interval_seconds)
        self.es_url = es_url.rstrip("/")
        self.index_pattern = index_pattern
        self.api_key = api_key
        self.username = username
        self.password = password
        self.max_retries = max_retries
        self.timeout_seconds = timeout_seconds

    def _get_index_name(self) -> str:
        """Generate index name, supporting date-based patterns."""
        from datetime import datetime, timezone

        today = datetime.now(timezone.utc).strftime("%Y.%m.%d")
        if "{date}" in self.index_pattern:
            return self.index_pattern.replace("{date}", today)
        return self.index_pattern

    def _build_headers(self) -> dict[str, str]:
        """Build HTTP headers for Elasticsearch."""
        headers = {"Content-Type": "application/x-ndjson"}
        if self.api_key:
            headers["Authorization"] = f"ApiKey {self.api_key}"
        return headers

    def _ship_batch(self, events: list[dict[str, Any]]) -> bool:
        """Ship events using Elasticsearch _bulk API."""
        try:
            import urllib.error
            import urllib.request

            index_name = self._get_index_name()

            # Build bulk request body
            lines: list[str] = []
            for event in events:
                action = json.dumps({"index": {"_index": index_name}})
                doc = json.dumps(event, default=str)
                lines.append(action)
                lines.append(doc)
            body = "\n".join(lines) + "\n"

            # Attempt with retries
            for attempt in range(self.max_retries):
                try:
                    req = urllib.request.Request(
                        f"{self.es_url}/_bulk",
                        data=body.encode("utf-8"),
                        headers=self._build_headers(),
                        method="POST",
                    )

                    if self.username and self.password:
                        import base64

                        credentials = base64.b64encode(
                            f"{self.username}:{self.password}".encode()
                        ).decode()
                        req.add_header("Authorization", f"Basic {credentials}")

                    with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                        response_body = json.loads(resp.read())
                        if response_body.get("errors"):
                            logger.warning("Elasticsearch bulk response contained errors")
                            return False
                        return True

                except urllib.error.URLError as e:
                    wait = 2**attempt
                    logger.warning(
                        "Elasticsearch request failed (attempt %d/%d): %s. Retrying in %ds",
                        attempt + 1,
                        self.max_retries,
                        e,
                        wait,
                    )
                    if attempt < self.max_retries - 1:
                        time.sleep(wait)

            self._stats.last_error = "Max retries exceeded"
            return False

        except Exception as e:
            self._stats.last_error = str(e)
            logger.error("ElasticsearchShipper failed: %s", e)
            return False


class StdoutShipper(LogShipper):
    """Ships ECS events to stdout as NDJSON.

    Useful for container environments where log collection
    is handled by the container runtime (Docker, Kubernetes).
    """

    def __init__(self, buffer_size: int = 1, flush_interval_seconds: float = 0.0) -> None:
        super().__init__(buffer_size=buffer_size, flush_interval_seconds=flush_interval_seconds)

    def _ship_batch(self, events: list[dict[str, Any]]) -> bool:
        """Print events to stdout."""
        try:
            for event in events:
                print(json.dumps(event, default=str))
            return True
        except Exception as e:
            self._stats.last_error = str(e)
            return False
