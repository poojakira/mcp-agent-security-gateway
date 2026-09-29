"""Tests for Cerberus-compatible telemetry normalization and fingerprinting."""

from __future__ import annotations

import re

import pytest

from mcp_monitor.production.cerberus import (
    build_envelope,
    build_event,
    derive_ip_fingerprints,
    fingerprint_value,
    normalize_source_ip,
    resolve_source_ip,
)


def test_fingerprint_matches_contract_vector() -> None:
    assert fingerprint_value("203.0.113.5", "tenant-test-salt") == "6cdeaf7f56c523fbc8056310c25982fa"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("203.0.113.5", "203.0.113.5"),
        ("203.0.113.5:443", "203.0.113.5"),
        ("[2001:db8::1]", "2001:db8::1"),
        ("[2001:db8::1]:443", "2001:db8::1"),
        ("for=192.0.2.60", "192.0.2.60"),
        ('for="[2001:db8::7]:8443"', "2001:db8::7"),
        ("::ffff:203.0.113.9", "203.0.113.9"),
    ],
)
def test_source_normalization(raw: str, expected: str) -> None:
    assert str(normalize_source_ip(raw)) == expected


@pytest.mark.parametrize("raw", ["", "unknown", "_hidden", "for=unknown", "not-an-ip"])
def test_source_normalization_rejects_invalid_values(raw: str) -> None:
    with pytest.raises(ValueError):
        normalize_source_ip(raw)


def test_untrusted_peer_ignores_forwarded_header() -> None:
    source = resolve_source_ip(
        "198.51.100.10",
        "203.0.113.5, 10.0.0.8",
        trusted_proxy_cidrs=("10.0.0.0/8",),
    )
    assert str(source) == "198.51.100.10"


def test_trusted_proxy_uses_and_normalizes_leftmost_forwarded_source() -> None:
    source = resolve_source_ip(
        "10.1.2.3",
        "for=203.0.113.5:443, 10.1.2.3",
        trusted_proxy_cidrs=("10.0.0.0/8",),
    )
    assert str(source) == "203.0.113.5"


def test_ipv4_fingerprint_inputs_match_contract() -> None:
    fields = derive_ip_fingerprints("203.0.113.5", "tenant-test-salt")
    assert fields == {
        "ip_fp": "6cdeaf7f56c523fbc8056310c25982fa",
        "ip_net_fp": "f2018a095debaa94c83d0ca99f558ffa",
        "ip_block_fp": "84e3733136cd156996e6bd9e29c869b4",
        "ip_family": "v4",
    }


def test_ipv6_fingerprint_inputs_match_contract() -> None:
    fields = derive_ip_fingerprints("2001:db8:abcd:1234::1", "tenant-test-salt")
    assert fields == {
        "ip_fp": "90ef41e60ade46bfcff2b4b5b52ce6c9",
        "ip_net_fp": "b5697095026186ac1d3a4c7aa69eed26",
        "ip_block_fp": "5f34769e1dec8fea3c335fbcf99038f2",
        "ip_family": "v6",
    }


def test_event_has_exact_closed_schema_and_zero_tokens() -> None:
    event = build_event(
        ts="2026-09-29T23:45:00.000Z",
        credential="credential-path-a",
        endpoint="/v1/inspect_call",
        tokens_in=0,
        tokens_out=0,
        latency_ms=17,
        status=200,
        source_ip="203.0.113.5",
        tenant_salt="tenant-test-salt",
        cost=None,
    )
    assert list(event) == [
        "ts",
        "key_fp",
        "endpoint",
        "tokens_in",
        "tokens_out",
        "latency_ms",
        "status",
        "ip_fp",
        "ip_net_fp",
        "ip_block_fp",
        "ip_family",
        "cost",
    ]
    assert event["tokens_in"] == 0
    assert event["tokens_out"] == 0
    assert event["cost"] is None
    for name in ("key_fp", "ip_fp", "ip_net_fp", "ip_block_fp"):
        assert re.fullmatch(r"[0-9a-f]{32}", event[name])


def test_distinct_credentials_produce_distinct_stable_key_fingerprints() -> None:
    salt = "tenant-test-salt"
    a1 = fingerprint_value("credential-path-a", salt)
    a2 = fingerprint_value("credential-path-a", salt)
    b = fingerprint_value("credential-path-b", salt)
    assert a1 == a2
    assert a1 != b


def test_envelope_uses_documented_fields_only() -> None:
    event = build_event(
        ts="2026-09-29T23:45:00.000Z",
        credential="credential-path-a",
        endpoint="/v1/inspect_output",
        tokens_in=0,
        tokens_out=0,
        latency_ms=8,
        status=200,
        source_ip="2001:db8::1",
        tenant_salt="tenant-test-salt",
    )
    envelope = build_envelope(
        [event],
        schema_version="1",
        client="mcp-agent-security-gateway",
        backfill=False,
    )
    assert set(envelope) == {"schema_version", "client", "backfill", "events"}
    assert envelope["events"] == [event]
