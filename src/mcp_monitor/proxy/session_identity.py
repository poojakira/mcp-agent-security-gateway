"""Prototype operator-verified, HMAC-bound MCP stdio session assertions.

NOT a substitute for OIDC, mTLS, external IdP authentication, credential
rotation, cross-node replay defense, or an authenticated session transport.
This opt-in interface must be invoked only by a trusted local operator.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

_TOKEN_PART = re.compile(r"[A-Za-z0-9_-]+\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_FIELDS = frozenset({"iss", "aud", "tenant", "sub", "sid", "iat", "exp"})
_PURPOSE = b"mcp-stdio-session-v1:"
_MAX_TOKEN_LENGTH = 4096


class SessionVerificationError(ValueError):
    """A signed gateway session assertion is invalid or unavailable."""


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise SessionVerificationError(f"Invalid session {label}")
    return value


def _unique_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SessionVerificationError("Duplicate session claim")
        result[key] = value
    return result


def _decode_base64url(part: str) -> bytes:
    if not _TOKEN_PART.fullmatch(part):
        raise SessionVerificationError("Malformed session encoding")
    try:
        data = base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))
    except (ValueError, base64.binascii.Error) as exc:
        raise SessionVerificationError("Malformed session encoding") from exc
    canonical = base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")
    if canonical != part:
        raise SessionVerificationError("Noncanonical session encoding")
    return data


@dataclass(frozen=True, slots=True)
class VerifiedSession:
    tenant: str
    subject: str
    session_id: str
    issuer: str
    audience: str

    @property
    def principal(self) -> str:
        """Tenant-scoped ACL key. Length prefix prevents ambiguous identities."""
        return f"{len(self.tenant)}:{self.tenant}:{self.subject}"


@dataclass(frozen=True, slots=True, repr=False)
class BoundSession:
    """Immutable assertion plus verifier; rechecked for every tool operation."""

    verifier: SessionVerifier = field(repr=False)
    assertion: str = field(repr=False)
    expected_session_id: str

    def verify(self) -> VerifiedSession:
        return self.verifier.verify(self.assertion, expected_session_id=self.expected_session_id)


class SessionVerifier:
    """Verify a short-lived operator-provisioned assertion with HMAC-SHA256.

    Assertion wire format: base64url(JSON claims) + "." + base64url(MAC).
    The MAC signs the ASCII payload section with a fixed domain separator.
    The shared key must be held in trusted local configuration, not in MCP
    arguments, CLI flags, logs, repositories, or downstream environment.
    """

    def __init__(
        self,
        *,
        key: bytes,
        issuer: str,
        audience: str,
        tenant: str,
        max_ttl_seconds: int = 3600,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if type(key) is not bytes or len(key) < 32:
            raise ValueError("Session verification key must contain at least 32 bytes")
        for label, value in (("issuer", issuer), ("audience", audience), ("tenant", tenant)):
            try:
                _identifier(value, label)
            except SessionVerificationError as exc:
                raise ValueError(f"Invalid trusted {label} configuration") from exc
        if (
            type(max_ttl_seconds) is not int
            or max_ttl_seconds <= 0
            or max_ttl_seconds > 3600
            or not callable(clock)
        ):
            raise ValueError("Invalid verifier timing configuration")
        self._key = key
        self._issuer = issuer
        self._audience = audience
        self._tenant = tenant
        self._max_ttl = max_ttl_seconds
        self._clock = clock

    def verify(self, assertion: str, *, expected_session_id: str) -> VerifiedSession:
        expected_session_id = _identifier(expected_session_id, "binding")
        if (
            not isinstance(assertion, str)
            or len(assertion) > _MAX_TOKEN_LENGTH
            or assertion.count(".") != 1
        ):
            raise SessionVerificationError("Malformed session assertion")
        payload_segment, mac_segment = assertion.split(".")
        payload = _decode_base64url(payload_segment)
        signature = _decode_base64url(mac_segment)
        if len(signature) != hashlib.sha256().digest_size:
            raise SessionVerificationError("Invalid session signature")
        expected_mac = hmac.new(
            self._key, _PURPOSE + payload_segment.encode("ascii"), hashlib.sha256
        ).digest()
        if not hmac.compare_digest(signature, expected_mac):
            raise SessionVerificationError("Invalid session signature")
        try:
            claims = json.loads(payload, object_pairs_hook=_unique_fields)
        except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
            raise SessionVerificationError("Malformed signed session claims") from exc
        if not isinstance(claims, dict) or claims.keys() != _FIELDS:
            raise SessionVerificationError("Invalid signed session claim set")
        issuer = _identifier(claims["iss"], "issuer")
        audience = _identifier(claims["aud"], "audience")
        tenant = _identifier(claims["tenant"], "tenant")
        subject = _identifier(claims["sub"], "subject")
        sid = _identifier(claims["sid"], "identifier")
        if (
            issuer != self._issuer
            or audience != self._audience
            or tenant != self._tenant
            or not hmac.compare_digest(sid, expected_session_id)
        ):
            raise SessionVerificationError("Session trust boundary mismatch")
        iat, exp = claims["iat"], claims["exp"]
        if type(iat) is not int or type(exp) is not int:
            raise SessionVerificationError("Invalid signed session lifetime")
        try:
            current = self._clock()
        except Exception as exc:
            raise SessionVerificationError("Session clock unavailable") from exc
        if (
            isinstance(current, bool)
            or not isinstance(current, int | float)
            or not math.isfinite(current)
        ):
            raise SessionVerificationError("Session clock unavailable")
        now = int(current)
        if iat < 0 or exp <= iat or exp - iat > self._max_ttl or iat > now + 30 or exp <= now:
            raise SessionVerificationError("Session expired or outside lifetime")
        return VerifiedSession(tenant, subject, sid, issuer, audience)

    def bind(self, assertion: str, *, expected_session_id: str) -> BoundSession:
        self.verify(assertion, expected_session_id=expected_session_id)
        return BoundSession(self, assertion, expected_session_id)
