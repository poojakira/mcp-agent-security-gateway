"""Bounded, network-free malformed egress destination regression tests."""

from __future__ import annotations

import pytest

from mcp_monitor.policy.policy_engine import PolicyEngine, ReasonCode


def _decision(destination: str, *, field: str = "url"):
    engine = PolicyEngine(
        allowed_servers={"sandbox"},
        allowed_tools={"http_get"},
        allowed_egress_hosts={"approved.example"},
    )
    return engine.evaluate(
        {
            "name": "http_get",
            "server_id": "sandbox",
            "arguments": {field: destination},
        }
    )


@pytest.mark.parametrize(
    "destination",
    [
        "ftp://approved.example/resource",
        "file://approved.example/path",
        "gopher://approved.example/resource",
        "https://user:pass@approved.example/path",
        "https://user@approved.example/path",
        "https://approved.example:99999/",
        "https://approved.example:-1/",
        "https://approved.example:notaport/",
        "https://approved.example:0/",
        "https://approved.example\\@other.example/",
        "https://approved.example\t.other.example/",
        "https://approved.example\n.other.example/",
        "approved.example/path",
        "approved.example?uri=secret",
        "approved.example#fragment",
        "approved.example:99999",
        "[::1]:0",
        "https://[fe80::1%25eth0]/",
    ],
)
def test_ambiguous_or_invalid_destinations_fail_closed(destination: str) -> None:
    result = _decision(destination)
    assert result.allowed is False
    assert result.reason_code == ReasonCode.DENY_EGRESS_MALFORMED


@pytest.mark.parametrize(
    "destination",
    [
        "https://approved.example/resource",
        "http://approved.example:8080/path",
        "approved.example",
        "approved.example:443",
    ],
)
def test_valid_declared_allowed_hosts_remain_compatible(destination: str) -> None:
    result = _decision(destination)
    assert result.allowed is True


def test_nested_bad_destination_denies_whole_call() -> None:
    engine = PolicyEngine(
        allowed_servers={"sandbox"},
        allowed_tools={"http_get"},
        allowed_egress_hosts={"approved.example"},
    )
    result = engine.evaluate(
        {
            "name": "http_get",
            "server_id": "sandbox",
            "arguments": {
                "url": "https://approved.example/data",
                "metadata": {"redirects": [{"destination": "file://approved.example/etc"}]},
            },
        }
    )
    assert result.reason_code == ReasonCode.DENY_EGRESS_MALFORMED
