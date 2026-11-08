"""Disposable JSON-RPC MCP-like fixture for Phase 5 container isolation only."""

from __future__ import annotations

import json
import os
import socket
import sys


def examine(kind: str) -> dict[str, object]:
    if kind == "network":
        # IANA TEST-NET-1, never a real external service or customer endpoint.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.settimeout(0.5)
            result = client.connect_ex(("192.0.2.1", 443))
        return {
            "network_denied": result != 0,
            "socket_error": result,
            "interfaces": [name for _, name in socket.if_nameindex()],
            "uid": os.getuid(),
        }
    if kind == "filesystem":
        try:
            with open("/phase5-host-root-write-probe", "w", encoding="utf-8") as output:
                output.write("synthetic")
            read_only = False
        except OSError:
            read_only = True
        return {"root_read_only": read_only, "uid": os.getuid()}
    return {"status": "ready", "uid": os.getuid()}


def main() -> None:
    for line in sys.stdin:
        try:
            request = json.loads(line)
            request_id = request.get("id")
            if request_id is None:
                continue
            if request.get("method") == "tools/call":
                kind = request.get("params", {}).get("arguments", {}).get("kind", "ready")
                result = examine(kind)
            else:
                result = {"status": "initialized"}
            message = {"jsonrpc": "2.0", "id": request_id, "result": result}
            print(json.dumps(message), flush=True)
        except Exception:
            # This fixture intentionally exposes no input or exception details.
            print(
                json.dumps(
                    {"jsonrpc": "2.0", "id": None, "error": {"code": -32603, "message": "Invalid"}}
                ),
                flush=True,
            )


if __name__ == "__main__":
    main()
