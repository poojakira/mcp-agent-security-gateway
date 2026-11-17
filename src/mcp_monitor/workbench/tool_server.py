"""First-party fixture server. Never evaluates input or opens supplied paths/URLs."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

VERSION = "2025-03-26"
TOOLS = ("read_note", "update_note", "append_note", "http_get", "crash", "timeout")


def serve(root: Path) -> None:
    """Serve a small, explicitly constrained JSON-RPC stdio MCP subset."""
    for line in sys.stdin:
        message = json.loads(line)
        identifier = message.get("id")
        method = message.get("method")
        if method.startswith("notifications/"):
            continue
        response = {"jsonrpc": "2.0", "id": identifier}
        params = message.get("params", {})
        if method == "initialize":
            client = params.get("clientInfo", {})
            if (
                not isinstance(params.get("protocolVersion"), str)
                or not isinstance(params.get("capabilities"), dict)
                or not isinstance(client, dict)
                or not isinstance(client.get("name"), str)
                or not isinstance(client.get("version"), str)
            ):
                response["error"] = {"code": -32602, "message": "Invalid initialization parameters"}
            else:
                response["result"] = {
                    "protocolVersion": VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "first-party-offline-fixture", "version": "0.1.0"},
                }
        elif method == "tools/list":
            response["result"] = {
                "tools": [
                    {
                        "name": name,
                        "description": "Constrained disposable fixture operation",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "path": {"type": "string", "enum": ["note.txt"]},
                                "text": {"type": "string", "maxLength": 2048},
                                "url": {"type": "string", "maxLength": 2048},
                                "context": {"type": "string", "maxLength": 8192},
                            },
                            "additionalProperties": False,
                        },
                    }
                    for name in TOOLS
                ]
            }
        elif method == "ping":
            response["result"] = {}
        elif method == "tools/call":
            name = params.get("name")
            args = params.get("arguments", {})
            if name not in TOOLS or not isinstance(args, dict):
                response["error"] = {"code": -32602, "message": "Unsupported tool or arguments"}
            else:
                with (root / "receipts.jsonl").open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps({"id": identifier, "tool": name}) + "\n")
                try:
                    if set(args) - {"path", "text", "url", "context"}:
                        raise ValueError("Unsupported argument")
                    if any(
                        not isinstance(value, str)
                        or len(value) > (8192 if key == "context" else 2048)
                        for key, value in args.items()
                    ):
                        raise ValueError("Arguments must be bounded strings")
                    if args.get("path", "note.txt") != "note.txt":
                        raise ValueError("Only disposable note.txt is accessible")
                    if name == "http_get":
                        raise ValueError("Outbound networking is unavailable in this server")
                    if name == "crash":
                        os._exit(7)
                    if name == "timeout":
                        time.sleep(30)
                    note = root / "note.txt"
                    if name in {"update_note", "append_note"}:
                        content = args.get("text", "")
                        if not isinstance(content, str) or len(content) > 2048:
                            raise ValueError("text must be a string of at most 2048 characters")
                        prior = note.read_text() if name == "append_note" else ""
                        note.write_text(prior + content, encoding="utf-8")
                    response["result"] = {
                        "content": [{"type": "text", "text": note.read_text(encoding="utf-8")}],
                        "isError": False,
                    }
                except ValueError as exc:
                    response["result"] = {
                        "content": [{"type": "text", "text": str(exc)}],
                        "isError": True,
                    }
        else:
            response["error"] = {"code": -32601, "message": "Unsupported method"}
        print(json.dumps(response), flush=True)


if __name__ == "__main__":
    serve(Path(sys.argv[1]))
