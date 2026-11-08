"""Phase 6: signed session validation and trusted-identity proxy enforcement.

All keys and tokens here are synthetic. No external identity or paid service.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json

import pytest

from mcp_monitor.policy.acl_guard import ACLGuard
from mcp_monitor.proxy.session_identity import SessionVerificationError, SessionVerifier
from mcp_monitor.proxy.stdio_proxy import StdioMCPProxy

KEY = b"synthetic-test-only-" + b"k" * 32
RESOURCE = "/synthetic/research.txt"
SID = "local-stdio-session-123"


def signed(
    *,
    tenant: str = "team-alpha",
    subject: str = "alice",
    session_id: str = SID,
    issuer: str = "local-gateway-auth",
    audience: str = "mcp-stdio",
    iat: int = 1000,
    exp: int = 1060,
    claims_override: dict | None = None,
    raw_payload: bytes | None = None,
    key: bytes = KEY,
) -> str:
    claims = {
        "iss": issuer,
        "aud": audience,
        "tenant": tenant,
        "sub": subject,
        "sid": session_id,
        "iat": iat,
        "exp": exp,
    }
    if claims_override:
        claims.update(claims_override)
    payload = raw_payload or json.dumps(claims, separators=(",", ":"), sort_keys=True).encode()
    encoded = base64.urlsafe_b64encode(payload).rstrip(b"=").decode()
    digest = hmac.new(key, b"mcp-stdio-session-v1:" + encoded.encode(), hashlib.sha256).digest()
    mac = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return encoded + "." + mac


def verifier(*, tenant: str = "team-alpha", clock=None) -> SessionVerifier:
    return SessionVerifier(
        key=KEY,
        issuer="local-gateway-auth",
        audience="mcp-stdio",
        tenant=tenant,
        clock=clock or (lambda: 1010),
    )


def test_valid_session_is_tenant_scoped_and_does_not_print_token() -> None:
    token = signed()
    binding = verifier().bind(token, expected_session_id=SID)
    assert binding.verify().principal == "10:team-alpha:alice"
    assert token not in repr(binding)
    assert KEY.hex() not in repr(binding)


@pytest.mark.parametrize(
    "modification",
    [
        {"issuer": "wrong-issuer"},
        {"audience": "wrong-audience"},
        {"tenant": "team-beta"},
        {"session_id": "session-b"},
        {"iat": 2000, "exp": 2050},
        {"iat": 800, "exp": 2000},
        {"iat": 1000, "exp": 1000},
        {"iat": True},
        {"claims_override": {"sub": ""}},
        {"claims_override": {"extra": "unknown"}},
        {"claims_override": {"exp": "1060"}},
    ],
)
def test_reject_wrong_trust_boundary_or_lifetime(modification: dict) -> None:
    with pytest.raises(SessionVerificationError):
        verifier().bind(signed(**modification), expected_session_id=SID)


@pytest.mark.parametrize("value", ["", "no-period", "not.base64.sign", "a." + "z" * 9000, None])
def test_reject_malformed_session_assertions(value: object) -> None:
    with pytest.raises(SessionVerificationError):
        verifier().bind(value, expected_session_id=SID)


def test_signature_tampering_and_wrong_key_fails_closed() -> None:
    token = signed()
    altered = token[:-1] + ("A" if token[-1] != "A" else "B")
    with pytest.raises(SessionVerificationError):
        verifier().bind(altered, expected_session_id=SID)
    with pytest.raises(SessionVerificationError):
        verifier().bind(signed(key=b"z" * 32), expected_session_id=SID)


def test_duplicate_signed_claims_rejected_even_with_correct_mac() -> None:
    payload = b'{"iss":"local-gateway-auth","iss":"forged"}'
    with pytest.raises(SessionVerificationError):
        verifier().bind(signed(raw_payload=payload), expected_session_id=SID)


def test_session_id_is_bound_to_one_stdio_session() -> None:
    token = signed()
    with pytest.raises(SessionVerificationError):
        verifier().bind(token, expected_session_id="different-stdio-session")


@pytest.mark.parametrize("key", [b"", b"k" * 31, "not-a-bytes-key", False])
def test_reject_weak_or_invalid_trust_keys(key: object) -> None:
    with pytest.raises(ValueError):
        SessionVerifier(key=key, issuer="trusted", audience="mcp", tenant="team")


def test_expiry_is_rechecked_after_binding() -> None:
    now = [1010]
    binding = verifier(clock=lambda: now[0]).bind(signed(), expected_session_id=SID)
    assert binding.verify().subject == "alice"
    now[0] = 1061
    with pytest.raises(SessionVerificationError, match="expired"):
        binding.verify()


class PausedTransport:
    def __init__(self, *, pause: bool = False) -> None:
        self.pause = pause
        self.started = asyncio.Event()
        self.unblock = asyncio.Event()
        self.sent: list[bytes] = []

    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        pass

    async def send(self, raw: bytes) -> None:
        self.sent.append(raw)

    async def receive(self) -> bytes:
        if self.pause:
            self.started.set()
            await self.unblock.wait()
        return b'{"jsonrpc":"2.0","id":7,"result":{"content":"SYNTHETIC_PRIVATE_DATA"}}'


def request(args: dict | None = None) -> bytes:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": args or {"path": RESOURCE},
            },
        }
    ).encode()


def make_proxy(*, tenant: str, transport: PausedTransport, clock=None, subject: str = "alice"):
    signed_token = signed(tenant=tenant, subject=subject)
    identity = verifier(tenant=tenant, clock=clock).bind(signed_token, expected_session_id=SID)
    grants = {"10:team-alpha:alice": {RESOURCE}}
    return StdioMCPProxy(
        command=["synthetic"],
        transport=transport,
        acl_guard=ACLGuard(grants),
        protected_resource_tools={"read_file": "path"},
        session_binding=identity,
    )


def test_session_principal_allows_correct_tenant_and_ignores_agent_spoofing() -> None:
    async def scenario() -> None:
        transport = PausedTransport()
        proxy = make_proxy(tenant="team-alpha", transport=transport)
        raw = await proxy.handle_message(
            request(
                {
                    "path": RESOURCE,
                    "principal": "10:team-beta:alice",
                    "tenant": "team-beta",
                }
            )
        )
        assert json.loads(raw)["result"]["content"] == "SYNTHETIC_PRIVATE_DATA"
        assert transport.sent != []

    asyncio.run(scenario())


def test_same_subject_in_other_tenant_cannot_read_across_boundary() -> None:
    async def scenario() -> None:
        transport = PausedTransport()
        proxy = make_proxy(tenant="team-beta", transport=transport)
        raw = await proxy.handle_message(request({"path": RESOURCE, "tenant": "team-alpha"}))
        assert json.loads(raw)["error"]["code"] == StdioMCPProxy.SECURITY_BLOCK_CODE
        assert transport.sent == []
        assert "SYNTHETIC_PRIVATE_DATA" not in raw.decode()

    asyncio.run(scenario())


def test_expired_session_fails_closed_before_forwarding() -> None:
    async def scenario() -> None:
        now = [1010]
        transport = PausedTransport()
        proxy = make_proxy(tenant="team-alpha", transport=transport, clock=lambda: now[0])
        now[0] = 1061
        raw = await proxy.handle_message(request())
        response = json.loads(raw)
        assert response["error"]["code"] == StdioMCPProxy.SECURITY_BLOCK_CODE
        assert "DENY_SESSION_AUTH" in response["error"]["data"]["patterns"]
        assert transport.sent == []

    asyncio.run(scenario())


def test_expiration_while_downstream_waits_suppresses_response() -> None:
    async def scenario() -> None:
        now = [1010]
        transport = PausedTransport(pause=True)
        proxy = make_proxy(tenant="team-alpha", transport=transport, clock=lambda: now[0])
        task = asyncio.create_task(proxy.handle_message(request()))
        try:
            await asyncio.wait_for(transport.started.wait(), timeout=3.0)
            now[0] = 1061
        finally:
            transport.unblock.set()
        raw = await asyncio.wait_for(task, timeout=3.0)
        result = json.loads(raw)
        assert "DENY_SESSION_AUTH" in result["error"]["data"]["patterns"]
        assert "SYNTHETIC_PRIVATE_DATA" not in raw.decode()
        assert len(transport.sent) == 1

    asyncio.run(scenario())


def test_legacy_principal_cannot_override_verified_binding() -> None:
    binding = verifier().bind(signed(), expected_session_id=SID)
    with pytest.raises(ValueError, match="Cannot mix"):
        StdioMCPProxy(
            command=["synthetic"],
            session_binding=binding,
            authenticated_principal="another-user",
        )


def test_untrusted_binding_type_rejected() -> None:
    with pytest.raises(ValueError, match="session_binding"):
        StdioMCPProxy(command=["synthetic"], session_binding={"tenant": "team-alpha"})
