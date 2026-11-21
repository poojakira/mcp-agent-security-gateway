"""Real policy/proxy invocation and independent disposable tool-side observations."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

from mcp_monitor.audit.log import AuditLog
from mcp_monitor.policy.policy_engine import PolicyEngine
from mcp_monitor.proxy.stdio_proxy import StdioMCPProxy, SubprocessTransport

VERSION = "0.1.0"
PROTOCOL = "2025-03-26"
INITIAL_NOTE = "Synthetic disposable sample. No customer data.\n"
PRESETS = {
    "read-only": {"read_note", "http_get", "crash", "timeout"},
    "read-write": {"read_note", "update_note", "append_note", "http_get", "crash", "timeout"},
}


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def provenance() -> dict:
    source = Path(__file__).resolve()
    root = source.parents[3]
    try:
        # A wheel installed under another repository must not inherit its HEAD.
        # Only the actual editable source layout can attest to this checkout.
        if root / "src/mcp_monitor/workbench/runtime.py" != source:
            raise ValueError("Installed distribution has no verified source checkout")

        def git(*arguments):
            return (
                subprocess.check_output(
                    ["git", *arguments], cwd=root, timeout=2, stderr=subprocess.DEVNULL
                )
                .decode()
                .strip()
            )

        if Path(git("rev-parse", "--show-toplevel")).resolve() != root:
            raise ValueError("The package is not rooted in this Git checkout")
        git("ls-files", "--error-unmatch", "src/mcp_monitor/workbench/runtime.py")
        sha = git("rev-parse", "HEAD")
        status = "DIRTY" if git("status", "--porcelain") else "CLEAN"
    except (OSError, subprocess.SubprocessError, ValueError):
        sha = "UNKNOWN"
        status = "UNKNOWN"
    return {
        "app_version": VERSION,
        "source_commit": sha,
        "source_status": status,
        "protocol_version": PROTOCOL,
    }


class FixtureTransport(SubprocessTransport):
    """Fixed executable, minimal environment and disposable current directory."""

    def __init__(self, root: Path):
        super().__init__(
            [sys.executable, "-I", str(Path(__file__).with_name("tool_server.py")), str(root)]
        )
        self.root = root
        self.tool_sends = 0

    async def start(self) -> None:
        self._process = await asyncio.create_subprocess_exec(
            *self.command,
            cwd=self.root,
            env={"PATH": os.defpath, "PYTHONIOENCODING": "utf-8"},
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            limit=self.MAX_FRAME_BYTES,
        )

    async def send(self, data: bytes) -> None:
        # The editor accepts pretty JSON; MCP stdio requires one JSON message per
        # line. The canonical proxy has already rejected duplicates/malformed JSON.
        framed = json.dumps(json.loads(data), separators=(",", ":")).encode() + b"\n"
        self.tool_sends += 1
        await super().send(framed)


async def execute(
    raw: str, preset: str = "read-only", guarded: bool = True, repeats: int = 1
) -> dict:
    """Every invocation gets a new workspace and server; no arbitrary target is accepted."""
    if not isinstance(raw, str) or len(raw.encode()) > 8192:
        raise ValueError("request must be a JSON-RPC string of at most 8192 bytes")
    if (
        preset not in PRESETS
        or type(guarded) is not bool
        or type(repeats) is not int
        or repeats not in (1, 2)
    ):
        raise ValueError("Invalid policy, guarded flag or repeat count")
    trace = str(uuid.uuid4())
    policy = PolicyEngine(allowed_servers={"local"}, allowed_tools=PRESETS[preset])
    with tempfile.TemporaryDirectory(prefix="mcp-workbench-") as temporary:
        root = Path(temporary)
        (root / "note.txt").write_text(INITIAL_NOTE, encoding="utf-8")
        transport = FixtureTransport(root)
        proxy = StdioMCPProxy(
            transport.command, transport=transport, policy_engine=policy, strict_mcp_methods=True
        )
        responses = []
        handshake = []
        error = None
        authorization = None
        try:
            message = json.loads(raw)
            if isinstance(message, dict) and message.get("method") == "tools/call":
                params = message.get("params", {})
                if isinstance(params, dict):
                    evaluator = (
                        policy
                        if guarded
                        else PolicyEngine(
                            allowed_servers={"local"}, allowed_tools=PRESETS["read-write"]
                        )
                    )
                    authorization = evaluator.evaluate(
                        {
                            "name": params.get("name"),
                            "server_id": "local",
                            "arguments": params.get("arguments", {}),
                        }
                    ).to_dict()
        except (ValueError, RecursionError):
            pass  # The canonical proxy produces the authoritative parse denial below.
        try:
            await proxy.start()
            for msg in [
                {
                    "jsonrpc": "2.0",
                    "id": "init",
                    "method": "initialize",
                    "params": {
                        "protocolVersion": PROTOCOL,
                        "capabilities": {},
                        "clientInfo": {"name": "mcp-security-workbench", "version": VERSION},
                    },
                },
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {"jsonrpc": "2.0", "id": "list", "method": "tools/list"},
            ]:
                answer = await asyncio.wait_for(proxy.handle_message(json.dumps(msg).encode()), 2)
                if answer:
                    handshake.append(json.loads(answer))
            transport.tool_sends = 0
            for _ in range(repeats):
                if guarded:
                    answer = await asyncio.wait_for(proxy.handle_message(raw.encode()), 1)
                else:
                    # Comparator uses the same parser/strict method boundary, only exact tool
                    # permission changes. Injection/egress protection stays enabled.
                    comparator = StdioMCPProxy(
                        transport.command,
                        transport=transport,
                        policy_engine=PolicyEngine(
                            allowed_servers={"local"}, allowed_tools=PRESETS["read-write"]
                        ),
                        strict_mcp_methods=True,
                    )
                    answer = await asyncio.wait_for(comparator.handle_message(raw.encode()), 1)
                responses.append(json.loads(answer) if answer else {"notification": "no response"})
        except (asyncio.TimeoutError, RuntimeError, ValueError, OSError) as exc:
            error = type(exc).__name__
        finally:
            await proxy.stop()
        note = (root / "note.txt").read_text(encoding="utf-8")
        receipts_path = root / "receipts.jsonl"
        receipts = (
            [json.loads(line) for line in receipts_path.read_text().splitlines()]
            if receipts_path.exists()
            else []
        )
        if transport.tool_sends == 0:
            outcome = "NOT_INVOKED"
        elif error:
            outcome = "UNKNOWN / REQUIRES_RECONCILIATION"
        elif any("error" in item or item.get("result", {}).get("isError") for item in responses):
            outcome = "CONFIRMED_FAILED"
        elif (
            receipts
            and len(receipts) == len(responses)
            and all(
                isinstance(item.get("result"), dict)
                and isinstance(item["result"].get("content"), list)
                and item["result"].get("isError") is False
                for item in responses
            )
        ):
            outcome = "CONFIRMED_SUCCEEDED"
        else:
            outcome = "UNKNOWN / REQUIRES_RECONCILIATION"
        configuration = {
            "preset": preset,
            "guarded": guarded,
            "repeats": repeats,
            "effective_tool_allowlist": sorted(PRESETS[preset if guarded else "read-write"]),
            "protocol_version": PROTOCOL,
        }
        report = {
            **provenance(),
            "trace_id": trace,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "input_sha256": digest(raw.encode()),
            "configuration_sha256": digest(json.dumps(configuration, sort_keys=True).encode()),
            "configuration": configuration,
            "policy": preset,
            "guarded": guarded,
            "repeats": repeats,
            "authorization_decision": authorization,
            "effective_identity": "single local operator; no verified credential identity",
            "authority": "fixed first-party fixture only; no user-selected server",
            "request": raw,
            "handshake": handshake,
            "responses": responses,
            "outcome": outcome,
            "error": error,
            "tool_state": {
                "note": note,
                "note_sha256": digest(note.encode()),
                "receipts": receipts,
            },
            "limitations": [
                "Permission OFF changes the tool allowlist only; other security checks remain ON.",
                "First-party constrained fixture, not OS containment of arbitrary servers.",
                "No exactly-once guarantee; repeating append_note has duplicate effects.",
                "No credential lifecycle, response PII filtering or latest MCP interoperability claim.",
            ],
        }
        audit = AuditLog(str(root / "audit.jsonl"))
        audit.append(
            "execution",
            {"trace_id": trace, "input_sha256": report["input_sha256"], "outcome": outcome},
        )
        report["audit"] = {
            "entries": json.loads(audit.export_json()),
            "chain_verified": audit.verify_chain()[0],
            "integrity": "Unkeyed hash chain; no protection against full rewrite",
        }
        return report
