"""Cerberus-compatible privacy-preserving telemetry helpers.

This module keeps raw API credentials and raw source addresses local. It
normalizes source addresses, derives the exact/network/block representations
required by the Cerberus event contract, and fingerprints those values with
HMAC-SHA256 under a customer-held tenant salt.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any

_MAX_INT32 = 2_147_483_647


def fingerprint_value(value: str, tenant_salt: str | bytes) -> str:
    """Return the first 32 lowercase hex characters of HMAC-SHA256(value)."""
    if not value:
        raise ValueError("fingerprint input must not be empty")
    key = tenant_salt.encode("utf-8") if isinstance(tenant_salt, str) else tenant_salt
    if not key:
        raise ValueError("tenant_salt must not be empty")
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()[:32]


def normalize_source_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Normalize an address-like source value to a bare canonical IP address.

    Accepted forms include a bare IPv4/IPv6 address, IPv4 with a port,
    bracketed IPv6 (with or without a port), and RFC 7239-style for= values.
    Values such as unknown are rejected. IPv4-mapped IPv6 addresses are
    converted back to IPv4 before any network derivation.
    """
    raw = value.strip()
    if not raw:
        raise ValueError("source address is empty")

    if raw.lower().startswith("for="):
        raw = raw[4:].strip()
    if len(raw) >= 2 and raw[0] == raw[-1] == '"':
        raw = raw[1:-1].strip()

    if raw.lower() in {"unknown", "_hidden"} or raw.startswith("_"):
        raise ValueError("source address is not an IP address")

    if raw.startswith("["):
        closing = raw.find("]")
        if closing <= 1:
            raise ValueError("invalid bracketed source address")
        host = raw[1:closing]
        suffix = raw[closing + 1 :]
        if suffix and not (suffix.startswith(":") and suffix[1:].isdigit()):
            raise ValueError("invalid bracketed source address suffix")
        raw = host
    elif raw.count(":") == 1 and "." in raw:
        host, possible_port = raw.rsplit(":", 1)
        if possible_port.isdigit():
            raw = host

    try:
        address = ipaddress.ip_address(raw)
    except ValueError as exc:
        raise ValueError("source address is not a valid IP address") from exc

    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def _parse_networks(
    cidrs: Iterable[str],
) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for cidr in cidrs:
        value = cidr.strip()
        if not value:
            continue
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError as exc:
            raise ValueError(f"invalid trusted proxy CIDR: {value}") from exc
    return tuple(networks)


def resolve_source_ip(
    peer_address: str,
    forwarded_for: str | None = None,
    trusted_proxy_cidrs: Iterable[str] = (),
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Resolve the source address according to the configured trust boundary.

    The socket peer is authoritative by default. X-Forwarded-For is used only
    when the peer itself belongs to a configured trusted proxy/network. For a
    trusted edge, the leftmost comma-separated value is treated as the client
    source and normalized before use.
    """
    peer = normalize_source_ip(peer_address)
    networks = _parse_networks(trusted_proxy_cidrs)
    peer_is_trusted_proxy = any(
        peer.version == network.version and peer in network for network in networks
    )

    if peer_is_trusted_proxy and forwarded_for:
        leftmost = forwarded_for.split(",", 1)[0].strip()
        return normalize_source_ip(leftmost)
    return peer


def derive_ip_fingerprints(
    source_ip: str | ipaddress.IPv4Address | ipaddress.IPv6Address,
    tenant_salt: str | bytes,
) -> dict[str, str]:
    """Derive Cerberus exact/network/block fingerprints for one source IP."""
    address = normalize_source_ip(str(source_ip))
    if isinstance(address, ipaddress.IPv4Address):
        family = "v4"
        network = ipaddress.ip_network(f"{address}/24", strict=False)
        block = ipaddress.ip_network(f"{address}/16", strict=False)
    else:
        family = "v6"
        network = ipaddress.ip_network(f"{address}/64", strict=False)
        block = ipaddress.ip_network(f"{address}/48", strict=False)

    exact_value = str(address)
    network_value = str(network)
    block_value = str(block)
    return {
        "ip_fp": fingerprint_value(exact_value, tenant_salt),
        "ip_net_fp": fingerprint_value(network_value, tenant_salt),
        "ip_block_fp": fingerprint_value(block_value, tenant_salt),
        "ip_family": family,
    }


def iso8601_utc(timestamp: float | None = None) -> str:
    """Return an ISO 8601 UTC timestamp with a trailing Z."""
    dt = (
        datetime.now(timezone.utc)
        if timestamp is None
        else datetime.fromtimestamp(timestamp, tz=timezone.utc)
    )
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _validate_non_negative_int(name: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if value < 0 or value > _MAX_INT32:
        raise ValueError(f"{name} must be between 0 and {_MAX_INT32}")


def build_event(
    *,
    ts: str,
    credential: str,
    endpoint: str,
    tokens_in: int,
    tokens_out: int,
    latency_ms: int,
    status: int,
    source_ip: str | ipaddress.IPv4Address | ipaddress.IPv6Address,
    tenant_salt: str | bytes,
    cost: float | int | None = None,
) -> dict[str, Any]:
    """Build one event with exactly the twelve Cerberus event fields."""
    if not ts or "T" not in ts:
        raise ValueError("ts must be an ISO 8601 timestamp")
    if not credential:
        raise ValueError("credential must not be empty")
    if not endpoint or len(endpoint) > 500:
        raise ValueError("endpoint must be between 1 and 500 characters")

    _validate_non_negative_int("tokens_in", tokens_in)
    _validate_non_negative_int("tokens_out", tokens_out)
    _validate_non_negative_int("latency_ms", latency_ms)
    _validate_non_negative_int("status", status)

    if cost is not None:
        if isinstance(cost, bool) or not isinstance(cost, int | float):
            raise TypeError("cost must be a non-negative number or null")
        if cost < 0 or cost != cost or cost in (float("inf"), float("-inf")):
            raise ValueError("cost must be finite and non-negative")

    ip_fields = derive_ip_fingerprints(source_ip, tenant_salt)
    return {
        "ts": ts,
        "key_fp": fingerprint_value(credential, tenant_salt),
        "endpoint": endpoint,
        "tokens_in": tokens_in,
        "tokens_out": tokens_out,
        "latency_ms": latency_ms,
        "status": status,
        **ip_fields,
        "cost": cost,
    }


def build_envelope(
    events: list[dict[str, Any]],
    *,
    schema_version: str,
    client: str,
    backfill: bool = False,
) -> dict[str, Any]:
    """Build the documented Cerberus transport envelope."""
    if not schema_version:
        raise ValueError("schema_version must not be empty")
    if not client:
        raise ValueError("client must not be empty")
    return {
        "schema_version": schema_version,
        "client": client,
        "backfill": bool(backfill),
        "events": events,
    }
