"""Tests for identity telemetry canonicalization and fingerprinting."""

from __future__ import annotations

import re

import pytest

from mcp_monitor.production.identity_telemetry import (
    build_envelope,
    build_event,
    build_single_event_envelope,
    derive_ip_fingerprints,
    event_fingerprint,
    fingerprint_value,
    normalize_source_ip,
    resolve_source_ip,
)


def test_fingerprint_matches_contract_vector() -> None:
    actual = fingerprint_value("203.0.113.5", "tenant-test-salt")
    expected = "6cdeaf7f56c523fbc8056310c25982fa"
    assert actual == expected


def test_fingerprint_matches_cerberus_hex_salt_contract() -> None:
    salt_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    actual = fingerprint_value("credential-path-a", salt_hex)
    expected = "3e0cca38db644fa55c487360cf2827b1"
    assert actual == expected


def test_64_character_non_hex_salt_uses_utf8_fallback() -> None:
    salt = "00" * 15 + " " + "11" * 16 + " "
    actual = fingerprint_value("credential-path-a", salt)
    expected = "4d7c6c191d34188a7a5ed7f2a53d07f6"
    assert actual == expected


def test_source_normalization() -> None:
    cases = (
        ("203.0.113.5", "203.0.113.5"),
        ("203.0.113.5:443", "203.0.113.5"),
        ("[2001:db8::1]", "2001:db8::1"),
        ("[2001:db8::1]:443", "2001:db8::1"),
        ("for=192.0.2.60", "192.0.2.60"),
        ('for="[2001:db8::7]:8443"', "2001:db8::7"),
        ("::ffff:203.0.113.9", "203.0.113.9"),
    )
    for raw, expected in cases:
        assert str(normalize_source_ip(raw)) == expected


def test_source_normalization_rejects_unknown() -> None:
    with pytest.raises(ValueError):
        normalize_source_ip("unknown")


def test_untrusted_peer_ignores_forwarded_header() -> None:
    source = resolve_source_ip(
        "198.51.100.10",
        "203.0.113.5, 10.0.0.8",
        trusted_proxy_cidrs=("10.0.0.0/8",),
    )
    assert str(source) == "198.51.100.10"


def test_trusted_proxy_uses_forwarded_source() -> None:
    source = resolve_source_ip(
        "10.1.2.3",
        "for=203.0.113.5:443, 10.1.2.3",
        trusted_proxy_cidrs=("10.0.0.0/8",),
    )
    assert str(source) == "203.0.113.5"


def test_ipv4_fingerprints_match_contract_inputs() -> None:
    fields = derive_ip_fingerprints("203.0.113.5", "tenant-test-salt")
    assert fields["ip_fp"] == "6cdeaf7f56c523fbc8056310c25982fa"
    assert fields["ip_net_fp"] == "f2018a095debaa94c83d0ca99f558ffa"
    assert fields["ip_block_fp"] == "84e3733136cd156996e6bd9e29c869b4"
    assert fields["ip_family"] == "v4"


def test_ipv6_fingerprints_match_contract_inputs() -> None:
    fields = derive_ip_fingerprints("2001:db8:abcd:1234::1", "tenant-test-salt")
    assert fields["ip_fp"] == "90ef41e60ade46bfcff2b4b5b52ce6c9"
    assert fields["ip_net_fp"] == "b5697095026186ac1d3a4c7aa69eed26"
    assert fields["ip_block_fp"] == "5f34769e1dec8fea3c335fbcf99038f2"
    assert fields["ip_family"] == "v6"


def test_event_has_closed_schema_and_zero_tokens() -> None:
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
    expected_fields = {
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
    }
    assert set(event) == expected_fields
    assert event["tokens_in"] == 0
    assert event["tokens_out"] == 0
    assert event["cost"] is None
    for name in ("key_fp", "ip_fp", "ip_net_fp", "ip_block_fp"):
        assert re.fullmatch(r"[0-9a-f]{32}", event[name])


def test_distinct_credentials_have_distinct_stable_fingerprints() -> None:
    salt = "tenant-test-salt"
    first = fingerprint_value("credential-path-a", salt)
    repeated = fingerprint_value("credential-path-a", salt)
    second = fingerprint_value("credential-path-b", salt)
    assert first == repeated
    assert first != second


def test_event_fingerprint_matches_confirmed_formula() -> None:
    actual = event_fingerprint("trace-abc:span-123", "tenant-test-salt")
    assert actual == "8ca91c1f7778f80f1e5c3ec0ab170428"


def test_event_fingerprint_is_stable_for_retry() -> None:
    salt = "tenant-test-salt"
    event_id = "stable-logical-request-id"
    assert event_fingerprint(event_id, salt) == event_fingerprint(event_id, salt)
    assert event_fingerprint(event_id, salt) != event_fingerprint("different-request-id", salt)


def test_envelope_uses_confirmed_live_contract() -> None:
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
    fp = event_fingerprint("event-001", "tenant-test-salt")
    envelope = build_envelope([event], [fp])

    assert envelope["schema_version"] == 1
    assert isinstance(envelope["schema_version"], int)
    assert envelope["client"] == "mcp-gateway/1.0.0"
    assert envelope["backfill"] is False
    assert envelope["events"] == [event]
    assert envelope["event_fps"] == [fp]
    assert re.fullmatch(r"[0-9a-f]{32}", envelope["event_fps"][0])


def test_envelope_rejects_non_positional_or_invalid_event_fps() -> None:
    event = {"ts": "2026-09-29T23:45:00.000Z"}
    with pytest.raises(ValueError, match="length"):
        build_envelope([event], [])
    with pytest.raises(ValueError, match="32 lowercase hex"):
        build_envelope([event], ["ABC"])


def test_single_event_envelope_does_not_expose_event_id() -> None:
    event = {"ts": "2026-09-29T23:45:00.000Z"}
    envelope = build_single_event_envelope(
        event=event,
        event_id="gateway-record-123",
        tenant_salt="tenant-test-salt",
    )
    assert envelope["events"] == [event]
    assert "event_id" not in envelope
    assert len(envelope["event_fps"]) == 1
