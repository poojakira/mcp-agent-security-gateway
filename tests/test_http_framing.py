from __future__ import annotations

import asyncio
from unittest.mock import patch

from mcp_monitor.production.config import Config
from mcp_monitor.production.server import ProductionServer


class _Writer:
    def __init__(self) -> None:
        self.buffer = bytearray()
        self.closed = False

    def write(self, data: bytes) -> None:
        self.buffer.extend(data)

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


def _request(raw: bytes) -> bytes:
    reader = asyncio.StreamReader()
    reader.feed_data(raw)
    reader.feed_eof()
    writer = _Writer()
    with patch.dict("os.environ", {}, clear=False):
        server = ProductionServer(Config())
    asyncio.run(server._handle_connection(reader, writer))
    return bytes(writer.buffer)


def test_duplicate_content_length_is_rejected():
    response = _request(
        b"POST /v1/inspect_call HTTP/1.1\r\n"
        b"Host: gateway\r\n"
        b"Content-Length: 2\r\n"
        b"Content-Length: 2\r\n"
        b"\r\n{}"
    )
    assert response.startswith(b"HTTP/1.1 400")


def test_transfer_encoding_is_rejected():
    response = _request(
        b"POST /v1/inspect_call HTTP/1.1\r\n"
        b"Host: gateway\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n0\r\n\r\n"
    )
    assert response.startswith(b"HTTP/1.1 400")
    assert b"Transfer-Encoding unsupported" in response


def test_absolute_form_request_target_is_rejected():
    response = _request(
        b"GET http://evil.example/v1/health HTTP/1.1\r\n"
        b"Host: gateway\r\n\r\n"
    )
    assert response.startswith(b"HTTP/1.1 400")


def test_oversized_header_line_is_rejected():
    value = b"a" * (8 * 1024 + 16)
    response = _request(
        b"GET /v1/health HTTP/1.1\r\n"
        + b"X-Large: "
        + value
        + b"\r\n\r\n"
    )
    assert response.startswith(b"HTTP/1.1 431")


def test_unsupported_method_is_rejected():
    response = _request(
        b"TRACE /v1/health HTTP/1.1\r\n"
        b"Host: gateway\r\n\r\n"
    )
    assert response.startswith(b"HTTP/1.1 405")


def test_valid_health_request_reaches_router():
    response = _request(
        b"GET /v1/health HTTP/1.1\r\n"
        b"Host: gateway\r\n\r\n"
    )
    assert response.startswith(b"HTTP/1.1 200")
    assert b'"status": "healthy"' in response
