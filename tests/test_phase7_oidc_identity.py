"""Phase 7: offline RS256 JWKS JWT verification and proxy revocation tests.

All RSA keys are ephemeral memory-only fixtures. No external IdP or secrets.
"""

from __future__ import annotations

import asyncio
import copy
import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from mcp_monitor.policy.acl_guard import ACLGuard
from mcp_monitor.proxy.oidc_identity import OfflineJWKSVerifier
from mcp_monitor.proxy.session_identity import SessionVerificationError
from mcp_monitor.proxy.stdio_proxy import StdioMCPProxy

ISSUER = "https://issuer.example.test/"
AUDIENCE = "mcp-gateway"
TENANT = "team-alpha"
SID = "stdio-session-01"
RESOURCE = "/synthetic/protected.txt"


class RevocationLedger:
    def __init__(self) -> None:
        self.revoked: set[tuple[str, str, str]] = set()
        self.fail = False

    def __call__(self, tenant: str, sid: str, jti: str) -> bool:
        if self.fail:
            raise RuntimeError("SYNTHETIC_REVOCATION_SECRET")
        return (tenant, sid, jti) not in self.revoked

    def revoke(self, *, sid: str = SID, jti: str = "jti-01") -> None:
        self.revoked.add((TENANT, sid, jti))


@pytest.fixture(scope="module")
def keys():
    return (
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
    )


def public_jwk(key, kid: str) -> dict:
    jwk = RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
    return jwk


def jwks(keys) -> dict:
    return {"keys": [public_jwk(keys[0], "key-01")]}


def token(keys, **changes) -> str:
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "tenant": TENANT,
        "sub": "alice",
        "sid": SID,
        "jti": "jti-01",
        "iat": now - 2,
        "nbf": now - 2,
        "exp": now + 120,
    }
    claims.update(changes.pop("claims", {}))
    header = {"kid": changes.pop("kid", "key-01"), "typ": "JWT"}
    header.update(changes.pop("header", {}))
    signing_key = changes.pop("key", keys[0])
    algorithm = changes.pop("algorithm", "RS256")
    assert not changes
    return jwt.encode(claims, signing_key, algorithm=algorithm, headers=header)


def make_verifier(keys, ledger, *, tenant: str = TENANT):
    return OfflineJWKSVerifier(
        issuer=ISSUER,
        audience=AUDIENCE,
        tenant=tenant,
        jwks=jwks(keys),
        keyset_version=1,
        is_active=ledger,
        max_ttl_seconds=600,
    )


def test_valid_asymmetric_jwt_uses_verified_tenant_principal(keys) -> None:
    ledger = RevocationLedger()
    value = token(keys)
    binding = make_verifier(keys, ledger).bind(value, expected_session_id=SID)
    assert binding.verify().principal == "10:team-alpha:alice"
    assert value not in repr(binding)


@pytest.mark.parametrize(
    "invalid_claims",
    [
        {"iss": "https://evil.example.test/"},
        {"aud": "other-api"},
        {"tenant": "team-beta"},
        {"sub": ""},
        {"sid": "another-session"},
        {"jti": ""},
        {"nbf": int(time.time()) + 360},
        {"exp": int(time.time()) - 1},
        {"exp": int(time.time()) + 3600},
        {"iat": "incorrect"},
        {"aud": ["mcp-gateway", "other"]},
    ],
)
def test_invalid_signed_claims_denied(keys, invalid_claims: dict) -> None:
    with pytest.raises(SessionVerificationError):
        make_verifier(keys, RevocationLedger()).bind(
            token(keys, claims=invalid_claims), expected_session_id=SID
        )


def test_tampering_signature_denied(keys) -> None:
    good = token(keys)
    payload = good.split(".")
    # Mutate a significant signature byte, not base64 trailing padding bits.
    payload[2] = ("A" if payload[2][0] != "A" else "B") + payload[2][1:]
    with pytest.raises(SessionVerificationError):
        make_verifier(keys, RevocationLedger()).bind(".".join(payload), expected_session_id=SID)


def test_alg_none_and_hmac_confusion_denied(keys) -> None:
    current = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "alice",
        "tenant": TENANT,
        "sid": SID,
        "jti": "jti-01",
        "iat": current - 2,
        "nbf": current - 2,
        "exp": current + 60,
    }
    unsigned = jwt.encode(claims, key="", algorithm="none", headers={"kid": "key-01"})
    confused = jwt.encode(
        claims, key=b"synthetic-only" * 4, algorithm="HS256", headers={"kid": "key-01"}
    )
    verifier = make_verifier(keys, RevocationLedger())
    for value in (unsigned, confused):
        with pytest.raises(SessionVerificationError):
            verifier.bind(value, expected_session_id=SID)


def test_attacker_controlled_jku_is_rejected_without_fetch(keys) -> None:
    value = token(keys, header={"jku": "https://evil.example.test/jwks.json"})
    with pytest.raises(SessionVerificationError, match="header"):
        make_verifier(keys, RevocationLedger()).bind(value, expected_session_id=SID)


def test_old_key_is_dropped_when_keys_rotate(keys) -> None:
    ledger = RevocationLedger()
    verifier = make_verifier(keys, ledger)
    old = verifier.bind(token(keys), expected_session_id=SID)
    assert old.verify().subject == "alice"
    verifier.rotate({"keys": [public_jwk(keys[1], "key-02")]}, version=2)
    with pytest.raises(SessionVerificationError, match="key"):
        old.verify()
    new = verifier.bind(token(keys, kid="key-02", key=keys[1]), expected_session_id=SID)
    assert new.verify().subject == "alice"


def test_keyset_rollback_and_invalid_rotation_fail_closed(keys) -> None:
    verifier = make_verifier(keys, RevocationLedger())
    binding = verifier.bind(token(keys), expected_session_id=SID)
    with pytest.raises(SessionVerificationError, match="Out-of-order"):
        verifier.rotate(jwks(keys), version=1)
    with pytest.raises(SessionVerificationError, match="resync"):
        binding.verify()
    bad = {"keys": [dict(public_jwk(keys[0], "key-01"), d="private-not-allowed")]}
    with pytest.raises(SessionVerificationError, match="Invalid trusted keyset"):
        verifier.rotate(bad, version=2)
    with pytest.raises(SessionVerificationError, match="resync"):
        binding.verify()
    verifier.rotate(jwks(keys), version=3)
    assert binding.verify().subject == "alice"


def test_duplicate_kids_and_private_jwk_rejected(keys) -> None:
    original = public_jwk(keys[0], "key-01")
    for bad in (
        {"keys": [original, copy.deepcopy(original)]},
        {"keys": [dict(original, d="private-material")]},
        {"keys": [dict(original, alg="HS256")]},
        {"keys": [dict(original, kty="oct")]},
        {"keys": []},
    ):
        with pytest.raises(SessionVerificationError):
            OfflineJWKSVerifier(
                issuer=ISSUER,
                audience=AUDIENCE,
                tenant=TENANT,
                jwks=bad,
                keyset_version=1,
                is_active=RevocationLedger(),
            )


def test_explicit_session_id_and_revocation(keys) -> None:
    ledger = RevocationLedger()
    verifier = make_verifier(keys, ledger)
    with pytest.raises(SessionVerificationError, match="binding"):
        verifier.bind(token(keys), expected_session_id="other-session")
    binding = verifier.bind(token(keys), expected_session_id=SID)
    ledger.revoke()
    with pytest.raises(SessionVerificationError, match="revoked"):
        binding.verify()


def test_revocation_outage_fails_closed_without_exception_secret(keys) -> None:
    ledger = RevocationLedger()
    verifier = make_verifier(keys, ledger)
    binding = verifier.bind(token(keys), expected_session_id=SID)
    ledger.fail = True
    with pytest.raises(SessionVerificationError, match="unavailable") as error:
        binding.verify()
    assert "SYNTHETIC_REVOCATION_SECRET" not in str(error.value)


class PausedTransport:
    def __init__(self, *, pause: bool = False) -> None:
        self.pause = pause
        self.waiting = asyncio.Event()
        self.release = asyncio.Event()
        self.sent: list[bytes] = []

    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        pass

    async def send(self, value: bytes) -> None:
        self.sent.append(value)

    async def receive(self) -> bytes:
        if self.pause:
            self.waiting.set()
            await self.release.wait()
        return b'{"jsonrpc":"2.0","id":9,"result":{"content":"SYNTHETIC_PRIVATE_MARKER"}}'


def request(method: str, *, args: dict | None = None, ident: int = 9) -> bytes:
    data = {"jsonrpc": "2.0", "id": ident, "method": method, "params": {}}
    if method == "tools/call":
        data["params"] = {
            "name": "read_file",
            "arguments": args or {"path": RESOURCE},
        }
    return json.dumps(data).encode()


def proxy_for(keys, ledger: RevocationLedger, transport: PausedTransport, *, tenant: str = TENANT):
    verifier = make_verifier(keys, ledger, tenant=tenant)
    binding = verifier.bind(token(keys, claims={"tenant": tenant}), expected_session_id=SID)
    return StdioMCPProxy(
        command=["synthetic"],
        transport=transport,
        acl_guard=ACLGuard({"10:team-alpha:alice": {RESOURCE}}),
        protected_resource_tools={"read_file": "path"},
        session_binding=binding,
    )


def test_tenant_spoofing_in_tool_args_cannot_override_bound_identity(keys) -> None:
    async def scenario():
        ledger = RevocationLedger()
        transport = PausedTransport()
        proxy = proxy_for(keys, ledger, transport)
        value = request("tools/call", args={"path": RESOURCE, "tenant": "team-beta", "sub": "bob"})
        reply = json.loads(await proxy.handle_message(value))
        assert reply["result"]["content"] == "SYNTHETIC_PRIVATE_MARKER"
        assert transport.sent == [value + b"\n"]

    asyncio.run(scenario())


def test_cross_tenant_identity_is_denied_by_acl(keys) -> None:
    async def scenario():
        transport = PausedTransport()
        proxy = proxy_for(keys, RevocationLedger(), transport, tenant="team-beta")
        response = json.loads(await proxy.handle_message(request("tools/call")))
        assert response["error"]["code"] == StdioMCPProxy.SECURITY_BLOCK_CODE
        assert transport.sent == []

    asyncio.run(scenario())


def test_expired_or_revoked_request_does_not_forward_any_mcp_method(keys) -> None:
    async def scenario():
        ledger = RevocationLedger()
        transport = PausedTransport()
        proxy = proxy_for(keys, ledger, transport)
        ledger.revoke()
        value = request("resources/read")
        reply = json.loads(await proxy.handle_message(value))
        assert reply["error"]["code"] == StdioMCPProxy.SECURITY_BLOCK_CODE
        assert "DENY_SESSION_AUTH" in reply["error"]["data"]["patterns"]
        assert transport.sent == []

    asyncio.run(scenario())


def test_revocation_during_resource_read_suppresses_returned_content(keys) -> None:
    async def scenario():
        ledger = RevocationLedger()
        transport = PausedTransport(pause=True)
        proxy = proxy_for(keys, ledger, transport)
        value = request("resources/read")
        task = asyncio.create_task(proxy.handle_message(value))
        try:
            await asyncio.wait_for(transport.waiting.wait(), timeout=3.0)
            ledger.revoke()
        finally:
            transport.release.set()
        raw = await asyncio.wait_for(task, timeout=3.0)
        reply = json.loads(raw)
        assert "DENY_SESSION_AUTH" in reply["error"]["data"]["patterns"]
        assert "SYNTHETIC_PRIVATE_MARKER" not in raw.decode()
        assert transport.sent == [value + b"\n"]

    asyncio.run(scenario())
