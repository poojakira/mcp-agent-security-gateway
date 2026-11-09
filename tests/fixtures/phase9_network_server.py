"""Disposable MCP-like stdio fixture for a Phase 9 Docker internal network."""

from __future__ import annotations

import json
import os
import socket
import sys
from urllib.parse import urlsplit


def probe(kind: str) -> dict[str, object]:
    if kind == "direct":
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.settimeout(0.6)
            result = client.connect_ex(("192.0.2.1", 443))
        return {"direct_denied": result != 0, "socket_error": result}
    if kind == "proxy":
        url = urlsplit(os.environ.get("HTTPS_PROXY", ""))
        if not url.hostname or not url.port:
            return {"proxy_reachable": False}
        with socket.create_connection((url.hostname, url.port), timeout=2.0) as conn:
            conn.sendall(b"GET /synthetic HTTP/1.1\r\nHost: fixture\r\n\r\n")
            status = conn.recv(100)
        return {"proxy_reachable": status.startswith(b"HTTP/1.1 200")}
    if kind == "secret":
        return {"host_secret_inherited": "PHASE9_SYNTHETIC_HOST_SECRET" in os.environ}
    if kind == "filesystem":
        try:
            with open("/phase9-root-write", "w", encoding="utf-8") as output:
                output.write("synthetic")
            denied = False
        except OSError:
            denied = True
        return {"root_write_denied": denied, "uid": os.getuid()}
    return {"status": "ready", "uid": os.getuid()}


def main() -> None:
    for raw in sys.stdin:
        try:
            value = json.loads(raw)
            if "id" not in value:
                continue
            args = value.get("params", {}).get("arguments", {})
            kind = args.get("kind", "ready")
            result = probe(kind)
            print(json.dumps({"jsonrpc": "2.0", "id": value["id"], "result": result}), flush=True)
        except Exception:
            print(json.dumps({
                "jsonrpc": "2.0", "id": None,
                "error": {"code": -32603, "message": "Fixture failed"},
            }), flush=True)


if __name__ == "__main__":
    main()
