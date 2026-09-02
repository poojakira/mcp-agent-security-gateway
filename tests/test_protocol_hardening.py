"""Hardening tests for the JSON-RPC adapter and 5-layer orchestrator.

These tests exercise the gateway's behaviour on hostile or malformed input that
a real MCP peer could send: oversized payloads, deeply nested "JSON bombs",
unicode edge cases, and structurally invalid JSON-RPC. The gateway sits in the
request path, so every one of these must be rejected deterministically rather
than crashing or exhausting resources.
"""

from __future__ import annotations

import json

import pytest

from mcp_monitor.layers.orchestrator import _flatten
from mcp_monitor.protocol.jsonrpc import JSONRPCError, MCPJSONRPCAdapter


def _tool_call(name: str = "read_file", arguments: dict | None = None) -> str:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        }
    )


# ---------------------------------------------------------------------------
# Oversized payloads
# ---------------------------------------------------------------------------


class TestOversizedPayloads:
    def test_oversized_string_rejected_before_parse(self) -> None:
        adapter = MCPJSONRPCAdapter(max_message_bytes=1024)
        # 4 KiB of raw JSON, well over the 1 KiB limit.
        oversized = _tool_call(arguments={"blob": "A" * 4096})
        assert len(oversized.encode("utf-8")) > 1024
        with pytest.raises(JSONRPCError) as exc:
            adapter.parse_message(oversized)
        assert exc.value.code == -32600
        assert "exceeds limit" in str(exc.value)

    def test_message_at_limit_is_accepted(self) -> None:
        adapter = MCPJSONRPCAdapter(max_message_bytes=100_000)
        msg = _tool_call(arguments={"blob": "A" * 1000})
        assert len(msg.encode("utf-8")) <= 100_000
        parsed = adapter.parse_message(msg)
        assert len(parsed) == 1

    def test_bytes_input_also_size_checked(self) -> None:
        adapter = MCPJSONRPCAdapter(max_message_bytes=512)
        oversized = _tool_call(arguments={"blob": "B" * 2048}).encode("utf-8")
        with pytest.raises(JSONRPCError):
            adapter.parse_message(oversized)

    def test_size_limit_uses_utf8_byte_length_not_char_count(self) -> None:
        # 4-byte emoji: with ensure_ascii=False the char count is small but the
        # UTF-8 byte length is ~4x, so the guard must measure bytes.
        adapter = MCPJSONRPCAdapter(max_message_bytes=200)
        payload = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"blob": "\U0001f4a5" * 100}},
            },
            ensure_ascii=False,
        )
        assert len(payload) < len(payload.encode("utf-8"))
        with pytest.raises(JSONRPCError):
            adapter.parse_message(payload)

    def test_default_limit_is_one_mib(self) -> None:
        adapter = MCPJSONRPCAdapter()
        assert adapter.max_message_bytes == 1_048_576


# ---------------------------------------------------------------------------
# Depth bombs
# ---------------------------------------------------------------------------


class TestDepthBombs:
    def test_deeply_nested_dict_rejected(self) -> None:
        adapter = MCPJSONRPCAdapter(max_depth=16)
        node: dict = {}
        cur = node
        for _ in range(50):
            cur["x"] = {}
            cur = cur["x"]
        with pytest.raises(JSONRPCError) as exc:
            adapter.parse_message(node)
        assert exc.value.code == -32600
        assert "nesting depth" in str(exc.value)

    def test_deeply_nested_list_rejected(self) -> None:
        adapter = MCPJSONRPCAdapter(max_depth=16)
        node: list = []
        cur = node
        for _ in range(50):
            child: list = []
            cur.append(child)
            cur = child
        with pytest.raises(JSONRPCError):
            adapter.parse_message(node)

    def test_shallow_payload_accepted(self) -> None:
        adapter = MCPJSONRPCAdapter(max_depth=16)
        parsed = adapter.parse_message(_tool_call(arguments={"a": {"b": {"c": 1}}}))
        assert len(parsed) == 1

    def test_depth_guard_does_not_itself_recurse(self) -> None:
        # A pathological 5000-deep structure must be rejected without the guard
        # blowing its own stack (iterative implementation).
        adapter = MCPJSONRPCAdapter(max_depth=64)
        node: dict = {}
        cur = node
        for _ in range(5000):
            cur["n"] = {}
            cur = cur["n"]
        with pytest.raises(JSONRPCError):
            adapter.parse_message(node)


class TestFlattenDepthBound:
    def test_flatten_is_depth_bounded(self) -> None:
        node: dict = {}
        cur = node
        for _ in range(5000):
            cur["n"] = {}
            cur = cur["n"]
        # Must not raise RecursionError; returns a marker instead.
        result = _flatten(node)
        assert "__max_depth_exceeded__" in result

    def test_flatten_shallow_values_preserved(self) -> None:
        result = _flatten({"a": 1, "b": ["x", "y"], "c": {"d": "z"}})
        assert 1 in result
        assert "x" in result and "y" in result and "z" in result


# ---------------------------------------------------------------------------
# Unicode edge cases
# ---------------------------------------------------------------------------


class TestUnicodeEdgeCases:
    def test_unicode_arguments_parsed(self) -> None:
        adapter = MCPJSONRPCAdapter()
        parsed = adapter.parse_message(
            _tool_call(arguments={"text": "café \u2603 \U0001f600 日本語"})
        )
        assert parsed[0].arguments["text"] == "café \u2603 \U0001f600 日本語"

    def test_null_byte_in_string_is_preserved(self) -> None:
        adapter = MCPJSONRPCAdapter()
        parsed = adapter.parse_message(_tool_call(arguments={"path": "a\u0000b"}))
        assert parsed[0].arguments["path"] == "a\u0000b"

    def test_surrogate_and_control_chars_do_not_crash(self) -> None:
        adapter = MCPJSONRPCAdapter()
        parsed = adapter.parse_message(_tool_call(arguments={"c": "\x07\x1b[31m\r\n\t"}))
        assert len(parsed) == 1

    def test_rtl_override_homoglyph_payload_parses(self) -> None:
        # Bidi/RTL override characters are a real tool-name spoofing vector; the
        # parser must surface them intact so downstream detectors can flag them.
        adapter = MCPJSONRPCAdapter()
        parsed = adapter.parse_message(_tool_call(name="read\u202efile", arguments={}))
        assert "\u202e" in parsed[0].name


# ---------------------------------------------------------------------------
# Malformed JSON-RPC
# ---------------------------------------------------------------------------


class TestMalformedJSONRPC:
    def test_invalid_json_raises_parse_error(self) -> None:
        adapter = MCPJSONRPCAdapter()
        with pytest.raises(JSONRPCError) as exc:
            adapter.parse_message("{not valid json")
        assert exc.value.code == -32700

    def test_wrong_jsonrpc_version_rejected(self) -> None:
        adapter = MCPJSONRPCAdapter()
        with pytest.raises(JSONRPCError) as exc:
            adapter.parse_message(json.dumps({"jsonrpc": "1.0", "method": "tools/call", "id": 1}))
        assert exc.value.code == -32600

    def test_missing_method_rejected(self) -> None:
        adapter = MCPJSONRPCAdapter()
        with pytest.raises(JSONRPCError):
            adapter.parse_message(json.dumps({"jsonrpc": "2.0", "id": 1}))

    def test_params_not_object_rejected(self) -> None:
        adapter = MCPJSONRPCAdapter()
        with pytest.raises(JSONRPCError) as exc:
            adapter.parse_message(
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": "oops",
                    }
                )
            )
        assert exc.value.code == -32602

    def test_tool_name_not_string_rejected(self) -> None:
        adapter = MCPJSONRPCAdapter()
        with pytest.raises(JSONRPCError):
            adapter.parse_message(
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {"name": 123, "arguments": {}},
                    }
                )
            )

    def test_empty_batch_rejected(self) -> None:
        adapter = MCPJSONRPCAdapter()
        with pytest.raises(JSONRPCError):
            adapter.parse_message("[]")

    def test_batch_skips_non_dict_entries_without_failing(self) -> None:
        adapter = MCPJSONRPCAdapter()
        batch = json.dumps(
            [
                "garbage",
                42,
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "ok", "arguments": {}},
                },
            ]
        )
        parsed = adapter.parse_message(batch)
        assert len(parsed) == 1
        assert parsed[0].name == "ok"

    def test_top_level_scalar_rejected(self) -> None:
        adapter = MCPJSONRPCAdapter()
        with pytest.raises(JSONRPCError) as exc:
            adapter.parse_message("42")
        assert exc.value.code == -32600

    def test_is_tool_call_request_swallows_errors(self) -> None:
        adapter = MCPJSONRPCAdapter()
        assert adapter.is_tool_call_request("{bad json") is False
