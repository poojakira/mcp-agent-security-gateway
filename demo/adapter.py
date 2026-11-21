import asyncio
import json

from mcp_monitor.workbench.runtime import execute

SPEC = {
    "title": "MCP Agent Security Gateway",
    "version": "0.1.0",
    "description": "Change one tool permission and inspect an actual first-party child, "
    "execution receipt and file-state hash.",
    "scenarios": [
        {"id": "read", "label": "Read synthetic note · permission ON"},
        {"id": "deny", "label": "Same write request · permission ON (read-only)"},
        {"id": "allow", "label": "Same write request · tool permission OFF"},
    ],
    "limitations": [
        "Notebook mode uses only these fixed synthetic requests; no user-selected server, path or arbitrary JSON input.",
        "Tool permission OFF changes only the allowlist; other gateway checks remain enabled.",
        "A real child runs in a disposable workspace; this is not arbitrary-server OS containment.",
        "No credential lifecycle, latest MCP conformance, output PII filter or durable external-action reconciliation.",
    ],
    "repository": "https://github.com/poojakira/mcp-agent-security-gateway/tree/codex/local-workbench-20261116",
}


def run(scenario):
    if scenario not in {item["id"] for item in SPEC["scenarios"]}:
        raise ValueError("Choose one of the documented synthetic scenarios")
    name = "read_note" if scenario == "read" else "update_note"
    arguments = {} if scenario == "read" else {"text": "Synthetic notebook demo note"}
    request = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
    )
    result = asyncio.run(execute(request, preset="read-only", guarded=scenario != "allow"))
    return {
        "summary": result["outcome"]
        + "; tool receipts="
        + str(len(result["tool_state"]["receipts"])),
        "engine_report": result,
    }
