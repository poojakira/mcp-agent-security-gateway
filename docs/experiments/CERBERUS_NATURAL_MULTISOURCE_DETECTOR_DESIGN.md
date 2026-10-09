# Cerberus: separate future natural multi-source detector validation

**Status:** DESIGN ONLY — NOT DEPLOYED, NOT ACTIVE, NO DETECTOR CLAIM  
**Created:** 2026-10-09  
**Branch:** `design/cerberus-natural-multisource-evaluation`  
**Related integration closeout:** [Cerberus integration validation PR #115](https://github.com/poojakira/mcp-agent-security-gateway/pull/115)

## Purpose

Keep two **separate evidence tracks** for the MCP Agent Security Gateway:

| Track | Purpose | State | What can be claimed |
|---|---|---|---|
| **A — Existing single-host integration** | Confirm authenticated MCP clients, the stable identity mapping, durable WAL/telemetry, and shipper → Cerberus delivery from the original gateway/NAT | Existing deployment / integration-validation closeout | **Integration validated; detector effectiveness not evaluated.** |
| **B — Future natural multi-source workload** | If an independently justified real workflow naturally invokes the **same identity** across multiple authentic host/source-address boundaries, determine whether Cerberus's **current** production fan-out detector can be evaluated | **Proposed only; no environment provisioned** | Nothing yet. Detector conclusions require actual observations and independent Cerberus confirmation. |

A Git branch only separates **source and changes**; it is **not** a separate service, machine, IP address, runtime volume, tenant, or traffic stream. Do not treat two branches on one computer as multi-source evidence.

## Hard boundaries

1. **Do not modify the original pilot:** Preserve its fixed three credentials, HMAC tenant salt, Docker project, state volume, delivery cursor, identity fingerprints, network topology, and existing event envelopes. Do not rebuild/redeploy it for the second track.
2. **No manufactured diversity:** Do not fake or rotate source addresses, spoof `X-Forwarded-For`, use VPN/proxy hops solely to trigger the rule, duplicate identities via test loops, or script a traffic generator to fill a baseline. Multi-source behavior must follow real usage rather than dictate it.
3. **No credential copying by default:** A second environment must use **separate environment-specific secrets, storage, and an explicitly approved Cerberus identity/tenant plan**. Reusing the existing pilot's three credential values across hosts would change their exposure and is prohibited absent a reviewed operational reason and explicit authorization. The detector's need for a logically stable identity across real sources does not, on its own, justify sharing a long-lived secret among hosts.
4. **No fabricated detector success:** A successful authenticated transport or visible event is not an alert, true positive, detector effectiveness, or acceptable behavioral baseline.
5. **No coupling to other MCP connectors:** Notion/OpenCode and unrelated credentials are out of scope.

## Conditional topology — only when justified by a real workflow

```text
 A: existing single-host pilot                     B: separately authorized future environment

 Existing MCP clients                              Real workload on host/site A ──┐
       │                                           (naturally distinct source)      │
       ▼                                                                           ▼
 Original persistent gateway/NAT                   Legitimate shared workload identity boundary
       │                                                                           ▲
       └─ durable queue → Cerberus                  Real workload on host/site B ──┘
          (integration evidence only)              (naturally distinct source)
                                                                 │
                                            independent authorized gateway path(s)
                                                                 │
                                              independent durable queues / shippers
                                                                 │
                                                      Cerberus validation context
                                            (separate evidence scope and classification)
```

**Important qualification:** Whether `same identity` can safely be a stable logical workload identity with per-host credentials — rather than one replicated `MCP_API_KEY` — depends on the actual Cerberus identity contract. Obtain an explicit mapping/attestation plan from Cerberus **before** any multi-host credential distribution. The current gateway's `key_fp` is tied to its authenticated credential, so separate uncorrelated credentials cannot be assumed to represent one detector identity.

For any distributed installation, provide each gateway its **own** WAL, audit volume, immutable identity queue, and cursor. The supplied Kubernetes manifest deliberately uses a single-writer local file store; do not horizontally scale multiple replicas onto one file-backed volume. Use independent durable volumes or an engineered concurrency-safe store.

## Prerequisites before beginning track B

- [ ] An existing, independently motivated application or agent workload **actually** spans multiple hosts or egress/source addresses; document why this topology exists independently of a detector test.
- [ ] Confirm real source-address provenance at the gateway boundary. Only trust forwarded headers from explicitly trusted infrastructure that removes untrusted values; never spoof addresses.
- [ ] Review data handling, operational permission, network paths and tenant isolation, and confirm that the deployment has an owner and a genuine non-test workload.
- [ ] Confirm with Cerberus the stable-identity mapping, tenant/salt contract, network fingerprint semantics, source-diversity prerequisites, event labeling, observation criteria, and how to distinguish detector-validation data from prior integration events.
- [ ] Approve an independent namespace/project, separate local/remote state, access controls and secrets management; never copy the original pilot's `.env`, volume, cursor or stored events.
- [ ] Define the data minimization and redaction review, no raw keys/IPs in public artifacts, and incident/rotation procedures if an approved cross-host identity is required.
- [ ] Identify useful, normal operational tasks and independent source variation; no synthetic or scheduled traffic solely for rule triggering.
- [ ] Set a clear start boundary for the **separate** detector phase and agree with Cerberus which events are eligible, how false positives are judged, and what completion means.

## Evidence collection for track B (when it exists)

Collect only bounded, authorized observations:

| Evidence | Verification |
|---|---|
| Workload origin and purpose | Document actual business/development activity and why different hosts are legitimately involved |
| Stable identity attribution | Cerberus confirms the same intended detector identity is recognized across distinct authentic sources, without exposing credentials |
| Real source diversity | Verify distinct peer/network provenance as seen by the gateway, rather than assuming two processes / two Docker containers imply distinct source addresses |
| Persistence and transport | Per-host WAL/queue counts, shipper 2xx responses, cursor checkpoints, source/event fingerprints; no raw secrets or IPs in public reports |
| Receiver confirmation | Cerberus confirms receipt and eligible classification, separately from local delivery |
| Detector behavior | Collect actual rule evaluations and decision/alert evidence; do not invent success or infer rule triggering merely from diverse inputs |
| Non-trigger behavior | Explicitly record quiet periods, missed/mismapped events and known limitations |
| Acceptance | Agree evaluation duration/volume and any detection quality criteria with Cerberus, rather than assuming a numeric threshold |

## Separation and closure policy

- Keep **Track A closed as integration validation** in its dedicated report (PR #115), regardless of future detector work.
- Keep **Track B unstarted** until all prerequisites are met. Creating this branch/document does not start a new pilot.
- Preserve distinct change history, artifact naming, deployment labels, logs, receipt confirmations, and final reports.
- If no legitimate multi-source workload arises, retain Track B as an archived design and **do not deploy a contrived environment**.
- This document contains **no deployment instructions requiring credentials**, no copied secrets, and no claim that new hosts, addresses or receiver-side detectors have been verified.

## Next decision

Only proceed to implementing a separate nonproduction environment when an actual multi-host workload exists and Cerberus explicitly agrees how the identity, source provenance and detector eligibility will be evaluated. Until then, the correct technical result is **integration validated; detector effectiveness not evaluated**.
