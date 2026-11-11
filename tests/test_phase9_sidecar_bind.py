"""Fail-closed address-selection regressions for the disposable Phase 9 sidecar."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_FIXTURE = Path(__file__).parent / "fixtures" / "phase9_sidecar_fixture.py"
_SPEC = importlib.util.spec_from_file_location("phase9_sidecar_fixture", _FIXTURE)
assert _SPEC is not None and _SPEC.loader is not None
_sidecar = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_sidecar)


@pytest.mark.parametrize("address", ["127.0.0.1", "0.0.0.0", "8.8.8.8", "::1"])
def test_sidecar_refuses_non_container_addresses(monkeypatch, address: str) -> None:
    monkeypatch.setattr(_sidecar.socket, "gethostname", lambda: "fixture")
    monkeypatch.setattr(_sidecar.socket, "gethostbyname", lambda _: address)
    with pytest.raises(RuntimeError, match="private container IPv4"):
        _sidecar._container_bind_address()


def test_sidecar_accepts_private_container_address(monkeypatch) -> None:
    monkeypatch.setattr(_sidecar.socket, "gethostname", lambda: "fixture")
    monkeypatch.setattr(_sidecar.socket, "gethostbyname", lambda _: "172.19.0.3")
    assert _sidecar._container_bind_address() == "172.19.0.3"
