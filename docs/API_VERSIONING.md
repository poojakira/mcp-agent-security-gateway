# API Versioning Strategy

> Versioning policy and guidelines for the mcp-agent-security-gateway HTTP API.

---

## Table of Contents

1. [Versioning Scheme](#versioning-scheme)
2. [URL Path Versioning](#url-path-versioning)
3. [Version Lifecycle](#version-lifecycle)
4. [Deprecation Policy](#deprecation-policy)
5. [Breaking vs Non-Breaking Changes](#breaking-vs-non-breaking-changes)
6. [Backward Compatibility Guarantees](#backward-compatibility-guarantees)
7. [Migration Guide Template](#migration-guide-template)
8. [Client Recommendations](#client-recommendations)

---

## Versioning Scheme

The gateway API uses **URL path versioning** as the primary mechanism:

```
https://gateway.example.com/v1/inspect
https://gateway.example.com/v2/inspect
```

### Why URL Path Versioning?

| Approach | Pros | Cons | Decision |
|----------|------|------|----------|
| URL path (`/v1/`) | Explicit, cacheable, easy to route | URL changes between versions | ✅ **Selected** |
| Header (`Accept-Version`) | Clean URLs | Hidden, harder to test/debug | ❌ |
| Query param (`?version=1`) | Simple | Not RESTful, caching issues | ❌ |

**Rationale:** For a security gateway, explicitness is paramount. URL-based versioning makes the API contract visible in every request, simplifies load balancer routing, and makes version-specific rate limiting trivial.

---

## URL Path Versioning

### URL Structure

```
/{version}/{resource}
```

### Current Versions

| Version | Status | Base Path | Released | Sunset Date |
|---------|--------|-----------|----------|-------------|
| `v1` | **Stable** | `/v1/` | 2024-03-01 | — |
| `v2` | **Current** | `/v2/` | 2025-01-15 | — |

### Endpoints by Version

#### v2 (Current)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v2/inspect` | Inspect an MCP tool call against all security layers |
| `POST` | `/v2/validate` | Validate a call without blocking (dry-run) |
| `GET` | `/v2/health` | Gateway health and layer status |
| `GET` | `/v2/health/layers` | Individual defense layer health |
| `GET` | `/v2/policy` | Current active policy summary |
| `PUT` | `/v2/policy` | Update policy (hot-reload) |
| `GET` | `/v2/audit` | Query audit log |
| `GET` | `/v2/metrics` | Prometheus-format metrics |

#### v1 (Stable — Deprecated 2025-07-15)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/inspect` | Inspect an MCP tool call |
| `GET` | `/v1/health` | Basic health check |
| `GET` | `/v1/policy` | Current policy |

### Version Discovery

Clients can discover available versions:

```http
GET /versions
```

Response:
```json
{
  "versions": [
    {
      "version": "v2",
      "status": "current",
      "base_url": "/v2/",
      "released": "2025-01-15"
    },
    {
      "version": "v1",
      "status": "deprecated",
      "base_url": "/v1/",
      "released": "2024-03-01",
      "sunset": "2026-01-15",
      "migration_guide": "https://docs.example.com/migration/v1-to-v2"
    }
  ]
}
```

---

## Version Lifecycle

Each API version progresses through these stages:

```
┌──────────┐     ┌──────────┐     ┌────────────┐     ┌─────────┐     ┌─────────┐
│  Alpha   │────▶│   Beta   │────▶│   Stable   │────▶│Deprecated│────▶│  Sunset │
└──────────┘     └──────────┘     └────────────┘     └─────────┘     └─────────┘
  (dev only)      (opt-in)         (recommended)      (6 months)       (removed)
```

| Stage | Duration | Guarantees | Client Action Required |
|-------|----------|------------|----------------------|
| **Alpha** | Variable | None — may change without notice | Do not use in production |
| **Beta** | 1–3 months | No breaking changes without notice | Opt-in testing encouraged |
| **Stable** | Until superseded | Full backward compatibility | Recommended for production |
| **Deprecated** | **6 months** | Maintained, receives security fixes only | Begin migration to next version |
| **Sunset** | — | Removed, returns `410 Gone` | Must have migrated |

---

## Deprecation Policy

### 6-Month Sunset Window

When a version is deprecated:

1. **Day 0:** Deprecation announced
   - `Sunset` header added to all responses
   - `Deprecation` header added to all responses
   - Changelog and documentation updated
   - Migration guide published

2. **Month 1–3:** Active migration period
   - Deprecation warnings in logs for consumers still using old version
   - Direct outreach to high-volume consumers

3. **Month 4–5:** Escalation period
   - Rate limits reduced on deprecated version (90% → 75% of normal)
   - Weekly deprecation warnings to remaining consumers

4. **Month 6:** Sunset
   - Version returns `410 Gone` with migration instructions
   - All traffic must use new version

### Deprecation Headers

All responses from deprecated versions include:

```http
HTTP/1.1 200 OK
Sunset: Sat, 15 Jan 2026 00:00:00 GMT
Deprecation: Wed, 15 Jul 2025 00:00:00 GMT
Link: </v2/inspect>; rel="successor-version"
X-API-Warn: "This version is deprecated. Migrate to /v2/ by 2026-01-15. See: https://docs.example.com/migration/v1-to-v2"
```

### Exception Process

If a consumer cannot migrate within 6 months:

1. File a request **at least 2 months before sunset**
2. Provide technical justification
3. Maximum extension: **3 additional months** (one-time only)
4. Extended consumers receive dedicated migration support

---

## Breaking vs Non-Breaking Changes

### Non-Breaking Changes (No Version Bump)

These changes are deployed to the **current** version without incrementing:

| Change Type | Example | Impact |
|-------------|---------|--------|
| Adding a new optional field to response | `"metadata": {...}` added | None — clients should ignore unknown fields |
| Adding a new endpoint | `GET /v2/stats` | None — doesn't affect existing endpoints |
| Adding optional request parameters | New query param `?verbose=true` | None — default behavior unchanged |
| Relaxing validation (accepting more inputs) | Allowing additional `method` values | None — previously valid requests still valid |
| Performance improvements | Faster response times | Positive |
| Bug fixes (correcting to documented behavior) | Fix: field was null, should be `[]` | May affect clients relying on buggy behavior |
| Adding new enum values to response fields | `status` gains value `"quarantined"` | Clients must handle unknown enum values gracefully |

### Breaking Changes (Require Version Bump)

These changes require a **new API version**:

| Change Type | Example | Why It Breaks |
|-------------|---------|---------------|
| Removing a field from response | Removing `legacy_id` | Clients may depend on it |
| Renaming a field | `user_id` → `principal_id` | Clients parse by name |
| Changing field type | `count: "5"` → `count: 5` | Type mismatch in clients |
| Removing an endpoint | Removing `GET /v1/legacy` | 404 for existing callers |
| Changing URL structure | `/inspect` → `/calls/inspect` | Hardcoded URLs break |
| Tightening validation (rejecting previously valid input) | Requiring `session_id` field | Previously valid requests fail |
| Changing error response format | New error schema | Client error handling breaks |
| Changing authentication mechanism | Bearer token → mTLS only | Auth flow changes |
| Changing default behavior | Default `mode` from `audit` → `enforce` | Silent behavior change |
| Changing HTTP method | `POST /inspect` → `PUT /inspect` | Client HTTP methods break |

### Gray Areas — How We Decide

For ambiguous cases, apply this test:

> "Will any well-behaved client, following our documented contract, break or behave differently?"

If **yes** → breaking change → new version.
If **no** → non-breaking → deploy to current version.

When in doubt, treat as breaking.

---

## Backward Compatibility Guarantees

For **Stable** versions, we guarantee:

1. **Existing endpoints** will not be removed
2. **Existing required request fields** will not change semantics
3. **Existing response fields** will not be removed or change type
4. **Default behavior** will not change
5. **Error codes** will not be reassigned
6. **Authentication mechanisms** will not change

Clients **must** be resilient to:

1. New fields appearing in responses (ignore unknown fields)
2. New optional parameters in requests
3. New endpoints being added
4. New enum values in response fields
5. Improved error messages (don't parse error strings)

---

## Migration Guide Template

Use this template when publishing a migration guide for a version transition:

---

### Migration Guide: v{OLD} → v{NEW}

**Published:** YYYY-MM-DD
**Sunset deadline for v{OLD}:** YYYY-MM-DD

#### Summary of Changes

| Change | v{OLD} Behavior | v{NEW} Behavior | Action Required |
|--------|-----------------|-----------------|-----------------|
| [Change 1] | [Old] | [New] | [What client must do] |
| [Change 2] | [Old] | [New] | [What client must do] |

#### Step-by-Step Migration

**Step 1: Update base URL**

```diff
- POST /v{OLD}/inspect
+ POST /v{NEW}/inspect
```

**Step 2: Update request payload**

```diff
  {
    "method": "tools/call",
    "params": {
      "name": "read_file",
-     "args": { "path": "/tmp/data" }
+     "arguments": { "path": "/tmp/data" }
    },
+   "context": {
+     "session_id": "required-in-v{NEW}"
+   }
  }
```

**Step 3: Update response handling**

```diff
  {
    "decision": "allow",
-   "reason": "Policy matched"
+   "result": {
+     "reason": "Policy matched",
+     "layers": ["input_validation", "policy_engine"],
+     "latency_ms": 2.3
+   }
  }
```

**Step 4: Update error handling**

```diff
  // Error responses now use RFC 7807 Problem Details
  {
-   "error": "invalid_request",
-   "message": "Missing required field"
+   "type": "https://gateway.example.com/errors/invalid-request",
+   "title": "Invalid Request",
+   "status": 400,
+   "detail": "Missing required field: params.name",
+   "instance": "/v2/inspect"
  }
```

#### Testing Your Migration

```bash
# Run against both versions in parallel to compare
diff <(curl -s /v1/inspect -d @payload.json | jq .) \
     <(curl -s /v2/inspect -d @payload_v2.json | jq .)
```

#### Rollback Plan

If issues arise after migrating to v{NEW}, revert your base URL to `/v{OLD}/` — it remains fully functional until sunset.

---

## Client Recommendations

### Best Practices for API Consumers

1. **Configure the base URL externally** — don't hardcode `/v1/` in application logic
2. **Ignore unknown response fields** — use permissive JSON parsing
3. **Handle unknown enum values** — have a default/fallback case
4. **Monitor the `Sunset` header** — alert when it appears
5. **Subscribe to the changelog** — get notified of upcoming deprecations
6. **Test against beta versions early** — opt into `/v2-beta/` during beta phases
7. **Use the `/versions` endpoint** to discover available versions programmatically

### SDK Versioning

Official SDKs follow the same 6-month deprecation policy:

```python
# SDK will warn when using deprecated API version
import mcp_gateway_client

client = mcp_gateway_client.Client(
    base_url="https://gateway.example.com",
    api_version="v2",  # Explicit version selection
)
```

### Version Negotiation

If a client requests a version that doesn't exist:

| Request | Response |
|---------|----------|
| Valid current version (`/v2/...`) | Normal response |
| Valid deprecated version (`/v1/...`) | Normal response + deprecation headers |
| Sunset version (`/v0/...`) | `410 Gone` + migration info |
| Unknown version (`/v99/...`) | `404 Not Found` + available versions |
| No version (`/inspect`) | `301 Redirect` to current version |
