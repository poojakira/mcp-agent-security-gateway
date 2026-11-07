"""ACL and CDC enforcement tests.

The backend search stub explicitly accepts a trusted allowed-ID filter.
Real search connectors must apply the filter within their retrieval query.
"""

import pytest

from mcp_monitor.policy.acl_guard import AccessDenied, ACLGuard, PermissionChange


def setup_guard():
    return ACLGuard({"alice": {"public", "alice-private"}, "bob": {"public"}})


def search_backend(query, allowed):
    all_docs = [
        {"resource_id": "public", "content": "shared"},
        {"resource_id": "alice-private", "content": "secret"},
        {"resource_id": "bob-private", "content": "other secret"},
    ]
    return [doc for doc in all_docs if doc["resource_id"] in allowed]


def test_pre_retrieval_acl_limits_results_to_principal():
    guard = setup_guard()
    assert [
        r["resource_id"] for r in guard.authorized_search("bob", "report", search_backend)
    ] == ["public"]


def test_unknown_principal_returns_nothing():
    guard = setup_guard()
    assert guard.authorized_search("unknown", "report", search_backend) == []


def test_no_identity_fails_closed():
    with pytest.raises(AccessDenied):
        setup_guard().authorized_search("", "report", search_backend)


def test_backend_leak_fails_closed():
    with pytest.raises(AccessDenied):
        setup_guard().authorized_search(
            "bob",
            "report",
            lambda query, allowed: [
                {"resource_id": "alice-private", "content": "secret"}
            ],
        )


def test_revocation_blocks_cached_resource():
    guard = setup_guard()
    guard.check("alice", "alice-private")
    guard.apply_change(PermissionChange(1, "alice", "alice-private", False))
    with pytest.raises(AccessDenied):
        guard.check("alice", "alice-private")
    assert [
        r["resource_id"] for r in guard.authorized_search("alice", "report", search_backend)
    ] == ["public"]


def test_grant_applies_to_next_retrieval():
    guard = setup_guard()
    guard.apply_change(PermissionChange(1, "bob", "bob-private", True))
    assert {
        r["resource_id"] for r in guard.authorized_search("bob", "report", search_backend)
    } == {"public", "bob-private"}


def test_out_of_order_event_disables_all_access_until_resync():
    guard = setup_guard()
    with pytest.raises(AccessDenied):
        guard.apply_change(PermissionChange(2, "bob", "public", False))
    with pytest.raises(AccessDenied):
        guard.check("alice", "public")
    guard.replace_snapshot({"bob": {"public"}}, sequence=2)
    guard.check("bob", "public")
    with pytest.raises(AccessDenied):
        guard.check("alice", "public")


def test_replayed_event_fails_closed():
    guard = setup_guard()
    guard.apply_change(PermissionChange(1, "bob", "public", False))
    with pytest.raises(AccessDenied):
        guard.apply_change(PermissionChange(1, "bob", "public", True))
    with pytest.raises(AccessDenied):
        guard.check("bob", "public")


def test_snapshot_rejects_rollback():
    guard = ACLGuard({"bob": {"public"}}, sequence=10)
    with pytest.raises(AccessDenied):
        guard.replace_snapshot({"bob": {"public"}}, sequence=9)


def test_empty_allowed_scope_never_calls_backend():
    called = []
    guard = ACLGuard({"bob": set()})
    result = guard.authorized_search(
        "bob", "query", lambda q, allowed: called.append(True)
    )
    assert result == []
    assert called == []


def test_revocation_after_search_before_use_is_checked():
    guard = setup_guard()
    results = guard.authorized_search("alice", "report", search_backend)
    assert any(r["resource_id"] == "alice-private" for r in results)
    guard.apply_change(PermissionChange(1, "alice", "alice-private", False))
    with pytest.raises(AccessDenied):
        guard.check("alice", "alice-private")
