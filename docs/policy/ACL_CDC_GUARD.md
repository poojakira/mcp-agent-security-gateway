# ACL-aware retrieval and permission-change enforcement

## Scope and honest status

This branch adds `src/mcp_monitor/policy/acl_guard.py`, an in-process reference
implementation for the two protections in the supplied design. It provides
**trusted-principal ACL filtering before search**, **post-retrieval validation**,
and **ordered permission changes (CDC) with fail-closed recovery**.

**It does not connect the stdio proxy to a production search index, identity
provider, CDC stream, or existing retrieval cache.** Do not advertise this as a
live enterprise ACL enforcement feature until those integrations are added and
tested. There is no evidence of a one-millisecond revocation guarantee.

## Example use

```python
from mcp_monitor.policy.acl_guard import ACLGuard, PermissionChange

guard = ACLGuard({"alice": {"doc-a", "doc-b"}, "bob": {"doc-a"}})

def index_search(query, allowed_resource_ids):
    # REQUIRED: enforce `allowed_resource_ids` in the real datastore query,
    # before vector similarity ranking/search results are computed.
    return [{"resource_id": "doc-a", "text": "example"}]

hits = guard.authorized_search("bob", "quarterly report", index_search)
guard.apply_change(PermissionChange(1, "bob", "doc-a", False))
# Following operations and any cached resource use MUST recheck:
guard.check("bob", "doc-a")  # raises AccessDenied
```

## Critical trust requirements

- The principal must come from authenticated session context, never MCP tool
  arguments or a language model.
- The ACL snapshot must be sourced from authoritative access control and bind
  each resource ID to the correct tenant and permissions.
- A search adapter must apply the allowed-resource filter **inside the index
  query**, not merely remove disallowed hits afterwards. The in-process guard
  also verifies results as defense in depth.
- CDC events must arrive through an authenticated feed, with durable ordering,
  sequence tracking and resynchronization. A missing event/replay invalidates
  access until a trusted snapshot is loaded.
- Recheck access immediately before displaying, exporting, caching, or executing
  on an already-retrieved result. Revocation cannot erase text already sent to
  the LLM or user; minimize exposure and partition/purge caches by principal,
  tenant and permission version.
- Enforce permissions on every resource-bearing tool, not only `search`.
- Deploying several gateway processes requires a shared, durable version/epoch
  or centralized policy service. The local lock and snapshot only guard one
  Python process. A process restart, temporary disconnection or failover must
  not accidentally restore revoked grants.
- Restricting search IDs does not secure the underlying object store by itself:
  file/download tools must also enforce authorization.
- Distinguish CDC freshness objective from demonstrated measurements.
  No sub-millisecond or one-millisecond performance claim is made.

## How to test

```bash
python -m pytest tests/test_acl_guard.py tests/test_stdio_policy_integration.py -v
python -m pytest tests/ -q
ruff check src/ tests/
ruff format --check src/ tests/
```

These are deterministic tests with a simulated search backend, **not**
production integration or external live event propagation validation.
