"""Offline JWKS JWT verification for an operator-bound MCP stdio identity pilot.

This module verifies externally signed RS256 tokens against a trusted,
operator-supplied PUBLIC JWKS. It never fetches remote keys or accepts an
agent-provided key or token. It is not a complete OIDC login/client channel.
"""

from __future__ import annotations

import math
import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from mcp_monitor.proxy.session_identity import SessionVerificationError, VerifiedSession

# The identity extra is opt-in; importing the ordinary gateway must keep
# working without PyJWT/cryptography installed.
try:
    import jwt
except ImportError:  # pragma: no cover - only exercised without the optional extra
    jwt = None

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_REQUIRED = ("iss", "aud", "sub", "tenant", "sid", "jti", "iat", "nbf", "exp")
_ALLOWED_JWK_FIELDS = frozenset({"kty", "kid", "use", "alg", "n", "e", "key_ops"})


def _valid_id(value: object, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise SessionVerificationError(f"Invalid verified session {label}")
    return value


@dataclass(frozen=True, slots=True, repr=False)
class OIDCSessionBinding:
    """Trusted operator binding, never created from untrusted MCP arguments."""

    verifier: OfflineJWKSVerifier = field(repr=False)
    token: str = field(repr=False)
    expected_session_id: str

    def verify(self) -> VerifiedSession:
        return self.verifier.verify(self.token, expected_session_id=self.expected_session_id)


class OfflineJWKSVerifier:
    """A strict RS256 verifier with local JWKS rotation and revocation hook.

    The operator authenticates a real issuer, provisions public keys, chooses
    a tenant and binds the STDIO client channel to one expected session ID.
    The callback is synchronous and MUST be non-blocking and trustworthy.
    A non-True result or callback error fails closed on each verification.
    """

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        tenant: str,
        jwks: dict[str, Any],
        keyset_version: int,
        is_active: Callable[[str, str, str], bool],
        max_ttl_seconds: int = 900,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if jwt is None:
            raise RuntimeError("Install the optional [oidc] dependencies to verify JWTs")
        if not isinstance(issuer, str) or len(issuer) > 256 or not issuer.startswith("https://"):
            raise ValueError("Issuer must be a trusted HTTPS URL")
        url = urlsplit(issuer)
        if not url.hostname or url.username or url.password or url.fragment or url.query:
            raise ValueError("Invalid issuer URL")
        for label, value in (("audience", audience), ("tenant", tenant)):
            try:
                _valid_id(value, label)
            except SessionVerificationError as exc:
                raise ValueError(f"Invalid trusted {label} configuration") from exc
        if type(keyset_version) is not int or keyset_version < 1:
            raise ValueError("Invalid trusted keyset version")
        if type(max_ttl_seconds) is not int or not 1 <= max_ttl_seconds <= 3600:
            raise ValueError("Invalid maximum token lifetime")
        if not callable(is_active) or not callable(clock):
            raise ValueError("A trusted revocation callback and clock are required")
        self._lock = threading.RLock()
        self._issuer = issuer
        self._audience = audience
        self._tenant = tenant
        self._is_active = is_active
        self._clock = clock
        self._max_ttl = max_ttl_seconds
        self._keys = self._compile_keys(jwks)
        self._version = keyset_version
        self._healthy = True

    @staticmethod
    def _compile_keys(jwks: dict[str, Any]) -> dict[str, Any]:
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
        from jwt.algorithms import RSAAlgorithm

        if (
            not isinstance(jwks, dict)
            or set(jwks) != {"keys"}
            or not isinstance(jwks["keys"], list)
            or not 1 <= len(jwks["keys"]) <= 8
        ):
            raise SessionVerificationError("Invalid trusted public JWKS")
        result: dict[str, Any] = {}
        for jwk in jwks["keys"]:
            if (
                not isinstance(jwk, dict)
                or not {"kid", "kty", "use", "alg", "n", "e"} <= set(jwk)
                or not set(jwk) <= _ALLOWED_JWK_FIELDS
                or jwk["kty"] != "RSA"
                or jwk["use"] != "sig"
                or jwk["alg"] != "RS256"
            ):
                raise SessionVerificationError("Unsupported public signing JWK")
            kid = _valid_id(jwk["kid"], "key id")
            if kid in result or ("key_ops" in jwk and jwk["key_ops"] != ["verify"]):
                raise SessionVerificationError("Duplicate or inappropriate signing JWK")
            try:
                key = RSAAlgorithm.from_jwk(jwk)
            except Exception as exc:
                raise SessionVerificationError("Invalid RSA public signing JWK") from exc
            if (
                not isinstance(key, RSAPublicKey)
                or key.key_size < 2048
                or key.public_numbers().e < 65537
            ):
                raise SessionVerificationError("Weak or non-public signing JWK")
            result[kid] = key
        return result

    def rotate(self, jwks: dict[str, Any], *, version: int) -> None:
        """Trust-boundary hook; never called with agent-controlled JWKS.

        Reject rollback and malformed snapshots by fencing this verifier until
        the operator supplies a valid, strictly newer complete keyset.
        """
        with self._lock:
            if type(version) is not int or version <= self._version:
                self._healthy = False
                raise SessionVerificationError("Out-of-order trusted keyset update")
            try:
                replacement = self._compile_keys(jwks)
            except Exception as exc:
                self._healthy = False
                raise SessionVerificationError("Invalid trusted keyset update") from exc
            self._keys = replacement
            self._version = version
            self._healthy = True

    def verify(self, token: str, *, expected_session_id: str) -> VerifiedSession:
        expected_session_id = _valid_id(expected_session_id, "session binding")
        if not isinstance(token, str) or not 1 <= len(token) <= 8192 or token.count(".") != 2:
            raise SessionVerificationError("Malformed session JWT")
        with self._lock:
            if not self._healthy:
                raise SessionVerificationError("Signing keyset requires trusted resync")
            try:
                header = jwt.get_unverified_header(token)
            except jwt.PyJWTError as exc:
                raise SessionVerificationError("Invalid JWT header") from exc
            if (
                not isinstance(header, dict)
                or set(header) != {"alg", "typ", "kid"}
                or header["alg"] != "RS256"
                or header["typ"] != "JWT"
            ):
                raise SessionVerificationError("Unsupported JWT header")
            kid = _valid_id(header["kid"], "key id")
            key = self._keys.get(kid)
            if key is None:
                raise SessionVerificationError("Untrusted signing key")
            try:
                claims = jwt.decode(
                    token,
                    key=key,
                    algorithms=["RS256"],
                    issuer=self._issuer,
                    audience=self._audience,
                    leeway=0,
                    options={"require": list(_REQUIRED), "strict_aud": True},
                )
            except jwt.PyJWTError as exc:
                raise SessionVerificationError("JWT signature or claims validation failed") from exc
            if not isinstance(claims, dict):
                raise SessionVerificationError("Invalid JWT claim envelope")
            for label in ("tenant", "sub", "sid", "jti"):
                _valid_id(claims.get(label), label)
            if claims["tenant"] != self._tenant or claims["sid"] != expected_session_id:
                raise SessionVerificationError("JWT tenant/session binding mismatch")
            if type(claims.get("aud")) is not str or claims["aud"] != self._audience:
                raise SessionVerificationError("JWT audience binding mismatch")
            if any(type(claims.get(label)) is not int for label in ("iat", "nbf", "exp")):
                raise SessionVerificationError("Invalid JWT timestamp type")
            iat, nbf, exp = claims["iat"], claims["nbf"], claims["exp"]
            try:
                now_value = self._clock()
            except Exception as exc:
                raise SessionVerificationError("Authentication clock unavailable") from exc
            if (
                isinstance(now_value, bool)
                or not isinstance(now_value, int | float)
                or not math.isfinite(now_value)
            ):
                raise SessionVerificationError("Authentication clock unavailable")
            now = int(now_value)
            if (
                iat < 0
                or nbf < iat - 30
                or iat > now + 30
                or nbf > now
                or exp <= now
                or exp <= iat
                or exp - iat > self._max_ttl
            ):
                raise SessionVerificationError("JWT timestamp outside trusted limits")
            try:
                active = self._is_active(self._tenant, claims["sid"], claims["jti"])
            except Exception as exc:
                raise SessionVerificationError("Session revocation status unavailable") from exc
            if type(active) is not bool or not active:
                raise SessionVerificationError("Session revoked or active status invalid")
            return VerifiedSession(
                self._tenant,
                claims["sub"],
                claims["sid"],
                self._issuer,
                self._audience,
            )

    def bind(self, token: str, *, expected_session_id: str) -> OIDCSessionBinding:
        self.verify(token, expected_session_id=expected_session_id)
        return OIDCSessionBinding(self, token, expected_session_id)
