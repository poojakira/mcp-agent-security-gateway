# Cerberus external pilot — integration validation closure

**Closure date:** 2026-10-09  
**Final disposition:** **INTEGRATION VALIDATED — DETECTOR EFFECTIVENESS NOT EVALUATED**  
**Scope:** One persistent MCP gateway, three fixed pilot identities, one host/NAT egress boundary.

> This closes the **integration-validation phase**, not a production behavioral-detector evaluation or a completed, statistically representative baseline.

## Decision and acceptance boundary

The three registered identities were authenticated through the persistent MCP Gateway; protected client requests produced durable gateway telemetry; the identity shipper delivered the events to Cerberus. Cerberus independently confirmed receiving the **initial three integration-validation events** and mapping each to the correct registered identity.

Cerberus also clarified that its **current production fan-out detector** requires an identity to appear naturally from multiple source addresses or hosts. Here, all three identities originate behind the same host/NAT. Three distinct identities behind one NAT are **not** a multi-source fan-out for one identity. No artificial source diversity, extra hosts, key rotation, or synthetic traffic was introduced to meet that detector precondition.

**Conclusion:** Integration validated. Fan-out detector effectiveness not evaluated in this topology.

## Dated evidence ledger

| When | Directly observed or confirmed | Evidence limit |
| --- | --- | --- |
| 2026-10-04 | Canonical preflight passed with the original three fixed pilot identities; Cerberus acknowledged the fingerprint prefixes and established the baseline-start boundary. | Identity setup, not evidence of behavioral detector efficacy. |
| 2026-10-09 — client validation | The real stdio MCP SDK initialized `cerberus-docs`, `cerberus-policy`, and `cerberus-detections`. One authenticated `list_files` request per identity completed without a tool error. | **Three deliberate validation calls**, not normal behavioral-baseline history. |
| 2026-10-09 — persistence/delivery | The persistent WAL and identity NDJSON queue each recorded three events; the durable shipper reported delivery in batches of **2 + 1** and advanced its byte-offset cursor through the queue. | Locally observed queue and successful HTTP delivery, not detector results. |
| 2026-10-09 — external acknowledgment | The Cerberus contact explicitly confirmed that **all three initial events were visible** and each mapped to its registered identity. | Independent receiver confirmation for these initial three events only. |
| 2026-10-09 — classification correction | Cerberus explained that validation calls used the normal `/v1/inspect_call` path and appeared as workload events. The contact said they were correcting that distinction on their side. | **Correction pending independent confirmation**. Do not count these calls toward a clean baseline. |
| 2026-10-09 — later engineering inspection | The scoped MCP paths were used for an actual read-only repository inspection of documentation, the policy workspace, and detection rules. Local WAL and identity queue counts rose from **3 to 8**; shipper logs reported **3 + 2** additional successful deliveries. | Five subsequent project-review events with local evidence of delivery; **their receipt/classification at Cerberus was not independently verified**. One session is not sustained behavioral history. |
| 2026-10-09 — topology assessment | Cerberus confirmed that the single persistent gateway/NAT setup is suitable for integration/identity/transport validation, but does not naturally exercise the source-diversity requirement of its current production fan-out detector. | Explicit architectural limitation; no claim that this detector fired or was evaluated. |

## Validated technical scope

- **Client and identity route:** Three stable credentials on dedicated, read-only MCP integrations, inspected through the authenticated gateway rather than bypassing it.
- **Gateway and persistence:** Protected requests reached the inspection path and generated WAL/audit and immutable queued identity telemetry on the persistent volume.
- **Outbound transport:** The separate shipper delivered the queued envelopes successfully over HTTPS and moved its durable delivery cursor only after successful responses.
- **Identity mapping:** Cerberus independently acknowledged attribution for the first three delivered requests.
- **Stable configuration:** Existing credentials, tenant HMAC salt, single-host/NAT topology, and shipper cursor were preserved.

The client-bridge work was verified in a **local runtime checkout**; publication of this report alone is **not a claim that the separate local integration code has been merged into public `main`**. The report is a bounded audit summary, not a production deploy, SOC acceptance report, or dump of private telemetry.

## What is NOT verified or claimed

1. **Fan-out detector effectiveness: NOT EVALUATED.** No demonstrated true-positive rate, false-positive rate, recall, precision, alert quality, production threshold triggering, or detector effectiveness.
2. **Required source diversity: NOT PRESENT.** One source/NAT for three independent identities does not satisfy the detector's multi-source-per-identity premise.
3. **Mature behavioral baseline: NOT ESTABLISHED.** The first three events were validation-only. Later scoped inspection calls do not constitute sustained representative workload history.
4. **Receiver reclassification: PENDING CONFIRMATION.** Cerberus said it would correct the initial events' classification; completion has not been independently verified.
5. **Additional receiver attribution: NOT INDEPENDENTLY VERIFIED.** The five subsequent events were confirmed delivered by the local shipper, not separately acknowledged at the Cerberus receiver.
6. **Host availability: BOUNDED.** Healthy containers and a configured `unless-stopped` restart policy were observed. Continuous uptime through reboots and unattended Docker Desktop startup were not demonstrated.
7. **Production deployment: NOT CLAIMED.** No customer workload, SOC operation, production-scale performance, multi-region topology, or production threat-detection accuracy is established.

This public report intentionally omits raw credentials, access tokens, tenant HMAC salt, exact source addresses, ingestion URL, and private event records.

## Closure checklist

- [x] Three declared identities authenticated and independently mapped by Cerberus
- [x] Protected MCP inspection path exercised via real clients
- [x] Durable queued telemetry and shipper delivery observed
- [x] Detector source-diversity limitation clarified and accepted
- [x] Integration evidence separated from baseline and detector-effectiveness claims
- [ ] Receiver-side completion of validation-event reclassification — **Cerberus follow-up, outside the closed integration scope**
- [ ] Sufficient natural source-diverse history and production fan-out detector evaluation — **separate future work only if a suitable real topology arises**

## Formal closure

**Integration-validation phase closed on 2026-10-09 with disposition: INTEGRATION VALIDATED; DETECTOR EFFECTIVENESS NOT EVALUATED.**

Retain the original deployment, credentials, tenant salt, and NAT topology unchanged. Do not regenerate credentials, reset the queue cursor, manufacture traffic, or add hosts purely to force the detector rule to fire. If a later genuine workload naturally uses the **same identity across multiple independent source addresses**, define a separate detector-validation exercise with Cerberus at that time.

## Related evidence and runbooks

- [Gateway runbook](../../RUNBOOK.md)
- [Repository verification metrics](../../VERIFIED_METRICS.md)
- [Threat model](../../THREAT_MODEL.md)

All values above are dated observations for this pilot; they are not replacements for CI/test metrics at other Git revisions.
