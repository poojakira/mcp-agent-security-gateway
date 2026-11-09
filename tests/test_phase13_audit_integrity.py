"""Fail-closed audit persistence and startup integrity regression tests."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from mcp_monitor.audit.log import AuditLog


def test_tampered_audit_log_rejected_on_restart(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(str(path))
    log.append("allowed", {"resource": "test"})
    log.append("denied", {"resource": "restricted"})

    records = [json.loads(line) for line in path.read_text().splitlines()]
    records[0]["data"]["resource"] = "forged"
    path.write_text(
        "\n".join(json.dumps(item) for item in records) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Audit chain integrity failed"):
        AuditLog(str(path))


def test_audit_persistence_failure_does_not_claim_success(tmp_path) -> None:
    log = AuditLog(str(tmp_path / "audit.jsonl"))
    with patch.object(log, "_persist", side_effect=OSError("synthetic disk failure")):
        with pytest.raises(OSError, match="synthetic disk failure"):
            log.append("allowed", {"resource": "test"})
    assert len(log) == 0
    assert log.verify_chain() == (True, None)
    with pytest.raises(OSError, match="not healthy"):
        log.append("another_event", {"resource": "test"})


def test_hmac_log_fails_if_reloaded_without_expected_key(tmp_path) -> None:
    path = tmp_path / "signed.jsonl"
    log = AuditLog(str(path), hmac_key=b"synthetic-test-only-key")
    log.append("denied", {"resource": "test"})
    with pytest.raises(ValueError, match="Audit chain integrity failed"):
        AuditLog(str(path), hmac_key=b"wrong-test-key")
