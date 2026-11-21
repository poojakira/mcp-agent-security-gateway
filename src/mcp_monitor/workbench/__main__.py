"""Loopback-only HTTP interface; no credentials or external services."""

from __future__ import annotations

import argparse
import asyncio
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from mcp_monitor.production.rate_limiter import RateLimiter
from mcp_monitor.workbench.runtime import execute, provenance

ASSETS = Path(__file__).parent


class Handler(BaseHTTPRequestHandler):
    """A serial server bounds execution to one child process at a time."""

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, _format, *args):
        pass  # No request payload or local operator data in stdout.

    def respond(self, status: int, value, kind="application/json"):
        payload = json.dumps(value).encode() if kind == "application/json" else value
        self.send_response(status)
        self.send_header("Content-Type", kind + "; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'",
        )
        self.end_headers()
        try:
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            # The client disconnected; do not attempt another response or tool action.
            pass

    def boundary(self) -> bool:
        authority = f"127.0.0.1:{self.server.server_port}"
        origin = self.headers.get("Origin")
        if (
            self.client_address[0] != "127.0.0.1"
            or self.headers.get("Host") != authority
            or (origin is not None and origin != f"http://{authority}")
        ):
            self.respond(403, {"error": "Only the local same-origin operator is allowed"})
            return False
        return True

    def do_GET(self):
        if not self.boundary():
            return
        if self.path == "/health":
            self.respond(200, {"status": "ok", **provenance()})
        elif self.path in {"/", "/app.js", "/style.css"}:
            name, kind = {
                "/": ("index.html", "text/html"),
                "/app.js": ("app.js", "text/javascript"),
                "/style.css": ("style.css", "text/css"),
            }[self.path]
            self.respond(200, (ASSETS / name).read_bytes(), kind)
        else:
            self.respond(404, {"error": "Not found"})

    def do_POST(self):
        if not self.boundary():
            return
        if self.path != "/api/execute":
            self.respond(404, {"error": "Not found"})
            return
        if not self.server.limiter.allow():
            self.respond(429, {"error": "Request limit reached; retry in one minute"})
            return
        if self.headers.get("Content-Type") != "application/json" or self.headers.get(
            "Transfer-Encoding"
        ):
            self.respond(415, {"error": "A bounded application/json body is required"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > 16384:
                self.respond(413, {"error": "Body must be between 1 and 16384 bytes"})
                return
            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, dict) or set(payload) - {
                "request",
                "preset",
                "guarded",
                "repeats",
            }:
                raise ValueError("Unsupported payload")
            report = asyncio.run(
                execute(
                    payload["request"],
                    payload.get("preset", "read-only"),
                    payload.get("guarded", True),
                    payload.get("repeats", 1),
                )
            )
        except (ValueError, KeyError, TypeError, RecursionError, UnicodeError):
            self.respond(400, {"error": "Invalid request payload"})
            return
        except Exception:
            self.respond(500, {"error": "Engine failed; no successful outcome established"})
            return
        self.respond(200, report)


def create_server(port=8761):
    server = HTTPServer(("127.0.0.1", port), Handler)
    server.limiter = RateLimiter(tokens_per_minute=30, burst_size=30)
    return server


def main():
    parser = argparse.ArgumentParser(description="Single-user local MCP Security Workbench")
    parser.add_argument("--port", type=int, default=8761)
    args = parser.parse_args()
    with create_server(args.port) as server:
        print(f"MCP Security Workbench: http://127.0.0.1:{server.server_port}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            # An operator interrupt ends the local loop; the context closes the server.
            pass


if __name__ == "__main__":
    main()
