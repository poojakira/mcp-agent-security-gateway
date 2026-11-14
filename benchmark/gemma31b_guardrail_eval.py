"""Offline end-to-end replay of *unreviewed* Gemma 4 31B MCP candidates.

Runs the actual StdioMCPProxy + policy engine + regex detector against a fake
downstream transport. Reports candidate-label outcomes, not verified accuracy.
Never starts Docker, fetches a model, or contacts a provider.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

from benchmark.gemma31b_data import DEFAULT_OUTPUT, MODEL, PROMPT_VERSION
from mcp_monitor.detectors.prompt_injection import PromptInjectionDetector
from mcp_monitor.policy.policy_engine import PolicyEngine
from mcp_monitor.proxy.stdio_proxy import StdioMCPProxy

MAX_CORPUS_BYTES = 100_000


class SyntheticTransport:
    """Tracks actual gateway forwarding, without executing a tool."""

    def __init__(self, response: bytes):
        self.response = response
        self.sent: list[bytes] = []

    async def start(self) -> None:
        return None

    async def stop(self) -> None:
        return None

    async def send(self, data: bytes) -> None:
        self.sent.append(data)

    async def receive(self) -> bytes:
        return self.response


def load_candidates(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    raw = path.read_bytes()
    if not raw or len(raw) > MAX_CORPUS_BYTES:
        raise ValueError("Invalid candidate corpus size")
    manifest_path = path.with_suffix(".manifest.json")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or manifest.get("sha256") != hashlib.sha256(raw).hexdigest():
        raise ValueError("Candidate corpus SHA-256 does not match manifest")
    if manifest.get("status") != "UNREVIEWED_GENERATED_DATA_NOT_EVALUATION_GROUND_TRUTH":
        raise ValueError("Only explicitly unreviewed candidate corpora are accepted")
    if manifest.get("model") != MODEL or manifest.get("prompt_version") != PROMPT_VERSION:
        raise ValueError("Unexpected model or prompt version")
    digest = manifest.get("model_digest")
    if not isinstance(digest, str) or len(digest) < 32:
        raise ValueError("Missing pinned local-model digest")
    try:
        cases = [json.loads(line) for line in raw.decode("utf-8").splitlines()]
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid candidate JSONL") from exc
    if len(cases) != 12 or manifest.get("count") != 12:
        raise ValueError("Expected exactly 12 paired model-generated candidates")
    ids: set[str] = set()
    contents: set[str] = set()
    for case in cases:
        if not isinstance(case, dict) or not all(
            isinstance(case.get(k), str)
            for k in (
                "id", "family", "surface", "text", "model_proposed_label",
                "review_status", "generator", "model_digest", "prompt_version",
            )
        ):
            raise ValueError("Invalid candidate case schema")
        if (
            case["review_status"] != "unreviewed"
            or case["generator"] != MODEL
            or case["model_digest"] != digest
            or case["prompt_version"] != PROMPT_VERSION
            or case["surface"] != "untrusted_mcp_content"
            or case["model_proposed_label"] not in ("benign", "adversarial")
            or not 40 <= len(case["text"]) <= 1200
        ):
            raise ValueError("Candidate provenance or label mismatch")
        if case["id"] in ids or case["text"] in contents:
            raise ValueError("Duplicated case ID or content")
        ids.add(case["id"])
        contents.add(case["text"])
    by_family: dict[str, list[str]] = {}
    for case in cases:
        by_family.setdefault(case["family"], []).append(case["model_proposed_label"])
    if len(by_family) != 6 or any(sorted(labels) != ["adversarial", "benign"] for labels in by_family.values()):
        raise ValueError("Expected six benign/adversarial pairs")
    return cases, manifest


def _gateway(response: bytes) -> tuple[StdioMCPProxy, SyntheticTransport]:
    downstream = SyntheticTransport(response)
    gateway = StdioMCPProxy(
        ["command-is-never-executed"],
        transport=downstream,
        server_id="synthetic",
        strict_mcp_methods=True,
        policy_engine=PolicyEngine(
            allowed_servers={"synthetic"},
            allowed_tools={"read_document"},
        ),
        detector=PromptInjectionDetector(enable_ml=False),
    )
    return gateway, downstream


async def replay_case(case: dict[str, Any], request_id: int) -> dict[str, Any]:
    method = "tools/list" if case["family"] == "tool_description_poisoning" else "tools/call"
    if method == "tools/list":
        response_content: dict[str, Any] = {
            "tools": [{"name": "read_document", "description": case["text"], "inputSchema": {"type": "object"}}]
        }
    else:
        response_content = {"content": [{"type": "text", "text": case["text"]}]}
    downstream_response = json.dumps(
        {"jsonrpc": "2.0", "id": request_id, "result": response_content}
    ).encode("utf-8")
    gateway, downstream = _gateway(downstream_response)
    request = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if method == "tools/call":
        request["params"] = {"name": "read_document", "arguments": {"path": "fictional-note.txt"}}
    raw = await gateway.handle_message(json.dumps(request).encode("utf-8"))
    parsed = json.loads(raw)
    error = parsed.get("error")
    blocked = isinstance(error, dict) and error.get("code") == StdioMCPProxy.SECURITY_BLOCK_CODE
    forwarded = len(downstream.sent) == 1
    if error is not None and not blocked:
        raise ValueError("Unexpected protocol or policy error during candidate replay")
    if blocked and case["text"] in raw.decode("utf-8"):
        raise ValueError("Blocked response leaked candidate contents")
    if not forwarded:
        raise ValueError("Expected authorized safe read/discovery to reach synthetic downstream")
    return {
        "id": case["id"],
        "family": case["family"],
        "model_proposed_label": case["model_proposed_label"],
        "downstream_forwarded": forwarded,
        "response_blocked": blocked,
        "detection_patterns": (
            error.get("data", {}).get("patterns", []) if blocked else []
        ),
        "surface": method,
    }


async def denied_tool_never_forwarded() -> bool:
    gateway, downstream = _gateway(
        b'{"jsonrpc":"2.0","id":901,"result":{"content":"should not reach this"}}'
    )
    req = {
        "jsonrpc": "2.0", "id": 901, "method": "tools/call",
        "params": {"name": "write_file", "arguments": {"path": "fictional-note.txt", "content": "synthetic"}},
    }
    result = json.loads(await gateway.handle_message(json.dumps(req).encode("utf-8")))
    return (
        result.get("error", {}).get("code") == gateway.SECURITY_BLOCK_CODE
        and len(downstream.sent) == 0
    )


async def evaluate_cases(cases: list[dict[str, Any]], manifest: dict[str, Any]) -> dict[str, Any]:
    results = [await replay_case(case, i + 100) for i, case in enumerate(cases)]
    blocked_attack = sum(r["response_blocked"] for r in results if r["model_proposed_label"] == "adversarial")
    released_benign = sum(not r["response_blocked"] for r in results if r["model_proposed_label"] == "benign")
    unauthorized_blocked = await denied_tool_never_forwarded()
    return {
        "model": MODEL,
        "model_digest": manifest["model_digest"],
        "candidate_corpus_sha256": manifest["sha256"],
        "mode": "offline_real_gateway_mock_downstream_regex_only",
        "candidate_labels": "UNREVIEWED_GENERATOR_PROPOSALS_NOT_GROUND_TRUTH",
        "real_gemma_inference_this_run": False,
        "actual_mcp_server_executed_this_run": False,
        "candidate_count": len(results),
        "model_proposed_adversarial_blocked": blocked_attack,
        "model_proposed_benign_released": released_benign,
        "model_proposed_labels_count": dict(Counter(r["model_proposed_label"] for r in results)),
        "unauthorized_write_blocked_before_send": unauthorized_blocked,
        "pass": unauthorized_blocked,
        "per_case": results,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay Gemma candidates through the actual MCP gateway")
    parser.add_argument("--input", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    cases, manifest = load_candidates(args.input)
    result = asyncio.run(evaluate_cases(cases, manifest))
    print(json.dumps(result, indent=2, sort_keys=True))
    if not result["pass"]:
        parser.exit(1, "Unauthorized write was forwarded\n")


if __name__ == "__main__":
    main()
