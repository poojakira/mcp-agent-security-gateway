# Repository research assessment

This reconciled assessment describes the implemented boundaries of the local workbench and existing inspection library. Earlier versions of this file remain in Git history. Uncited competitor certification claims, subjective effectiveness ratings and unsupported market/incident statistics have been removed; they are not evidence of this repository's behavior.

## Research question and implementation

Can an agent developer distinguish a policy decision from an observed tool-side outcome before integrating a privileged tool? The browser submits editable MCP JSON-RPC to the actual PolicyEngine/StdioMCPProxy. A fixed first-party stdio child operates on a disposable synthetic note. The report combines authorization, actual response, receipts and independently read state. A second execution changes only the exposed tool allowlist and uses another fresh target.

The software is stdlib-first, with a declared Python-3.10 `tomli` compatibility dependency and optional server/ML/development packages. Repository license terms are in [LICENSE](LICENSE); this assessment does not label all material open source or infer rights from public visibility.

## Evidence and reproducibility

[VERIFIED_METRICS.md](VERIFIED_METRICS.md) distinguishes the published source `4b6bb486d83f4410037113e64848a22e4a06f713` (829 passed, zero skipped, 81.80446084185813% statement coverage) from older snapshots and pending later-head verification. The full commands, UTC timing, environment, artifact checksums and independent review are linked from [docs/EVIDENCE.md](docs/EVIDENCE.md). A passing suite is bounded regression evidence, not population-level precision/recall.

The named prompt-injection collection has 69 entries at that implementation source. A count does not establish coverage against novel/adaptive attacks. The separate bundled catalog, SIEM fixture metrics and microbenchmarks have their own [historical evidence boundaries](docs/archive/HISTORICAL_EVIDENCE.md).

## What is established within the tested workflow

- Browser input invokes the real proxy/policy and an actual constrained child process.
- Read-only denial prevents a write operation from being forwarded; allowed comparison can change the note.
- Receipts/state support confirmed outcomes. Crash/timeouts retain UNKNOWN rather than infer success.
- Export redaction, fixed path, bounded HTTP input, origin checks and inert text rendering have named executable checks.
- Repeated append demonstrates duplicate effects; no exactly-once result is inferred.

The architecture, threat map, acceptance matrix and source/test pointers are consolidated in [docs/WORKBENCH.md](docs/WORKBENCH.md) and [THREAT_MODEL.md](THREAT_MODEL.md).

## Strongest counterarguments

A controlled first-party fixture cannot establish safety for arbitrary external tools. A server may perform a hidden operation below the MCP layer while returning an innocuous result; argument inspection alone cannot observe that side effect. Network egress policy returns decisions and is not packet interception. Optional host-monitor code is not evidence of a deployed kernel boundary. Initial manifest approval depends on trusted publisher/operator choices, and unkeyed logs can be rewritten completely.

Heuristic detectors have false positives and false negatives. Supplied input can quote attack-like instructions legitimately. No representative held-out attack/benign benchmark, field incident reduction, causal MTTD/MTTR improvement or universal security guarantee is established. Optional ML signals do not remove those limitations.

## Release decision

**PARTIAL.** Current MCP conformance/cancellation/concurrency, authenticated credential lifecycle, output PII filtering, arbitrary-server isolation, durable external action reconciliation, externally anchored logs and deployment-specific security/privacy/recovery signoff remain incomplete or unverified. Unique advanced execution/revocation work is preserved and has not been silently merged. Read the [release assessment](docs/EVIDENCE.md), not a research rating, before using this code beyond the supported local evaluation.
