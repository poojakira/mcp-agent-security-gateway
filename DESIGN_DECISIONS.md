# Design Decisions

This document explains why the MCP Agent Security Gateway is built the way it is. Not just what it does — why this architecture and not something else. I wrote this for anyone reviewing the design who works on agent security (particularly multi-agent orchestration, sandboxed execution, or delegated credential management).

## Why a proxy at all?

The obvious alternative is a library that agents import and call before each tool invocation. I rejected that because:

1. **Agents don't own their code.** If you're running Claude, GPT-4, or any hosted agent, you can't modify the agent's tool-calling logic. A proxy requires zero changes to the agent.
2. **Defense-in-depth requires independence.** A library inside the agent process can be bypassed by the same prompt injection that compromises the agent. An external proxy can't be turned off by the agent it protects.
3. **Observability across agents.** When you have 15 agents calling tools, you want one enforcement point with one audit log — not 15 libraries with 15 log formats.

The downside is latency. A proxy adds a hop. At 0.015ms average, this doesn't matter in practice — tool server responses are 50-500ms.

## Why 5 layers?

I tried 3 layers first (trust, policy, content inspection). The problem was that Layer 3 (content inspection) was doing too many unrelated things — checking for shell commands, scanning for PII, running injection rules, and evaluating egress patterns. Bugs in one check affected others. Latency was unpredictable because expensive regex patterns ran on every request.

I split it into 5 based on a principle: **each layer answers exactly one trust question, and cheaper checks run before expensive ones.**

| Layer | Trust Question | Cost |
|-------|---------------|------|
| 1: Server Trust | Do I trust the identity of the server I'm sending this to? | ~0.001ms (hash lookup) |
| 2: Tool-Call Policy | Is this tool allowed to be called with these argument types? | ~0.002ms (schema validation) |
| 3: Process-Spawn Eval | Does this try to execute a system process? | ~0.003ms (pattern match on a short blocklist) |
| 4: Semantic Intent | Does the content contain injection, PII, or manipulation? | ~0.008ms (50+ regex rules, normalization) |
| 5: Network Egress | Does this send data to an unexpected destination? | ~0.001ms (domain check) |

Layers 1-3 reject ~40% of malicious requests before Layer 4 (the expensive one) runs. This keeps the p99 at 0.04ms.

I considered splitting Layer 4 further (separate PII layer, separate injection layer) but it didn't improve anything — those checks share the same normalized representation of the request, and splitting them would mean normalizing twice.

Seven layers was also tested. I had "argument type validation" and "argument value validation" as separate layers. In practice, you always check both at the same time — schema validation already looks at values. Splitting them added latency with no security benefit.

## Why not ML-based detection?

Layer 4 uses 50+ regex-based rules, not a classifier. This is deliberate.

1. **Determinism.** I need to explain to an incident responder exactly why a request was blocked. "Rule PI-017 matched the pattern 'ignore.*previous.*instructions' in the argument at offset 42" is actionable. "The classifier scored 0.73" is not.
2. **No training data chicken-and-egg.** MCP tool-call injection is new. There isn't enough real-world data to train a classifier that generalizes. The rules I wrote come from reading actual attack patterns in prompt injection research (Greshake et al., not synthetic data).
3. **Latency.** Even a small model adds 1-10ms. The whole point of this proxy is sub-millisecond.
4. **False positive cost.** A false positive means a legitimate tool call gets blocked and the agent fails. In a production pipeline, that breaks a user's workflow. Regex rules are auditable and tunable per-tool; a classifier is not.

I expect ML-based detection to make sense once MCP is widely deployed and there's enough real traffic to train on. For now, rules are the right call.

## Why SHA-256 hash-chained audit logs?

Standard append-only logs can be truncated — you delete the last N entries and nobody notices. Hash chaining makes that detectable: each entry includes `sha256(previous_entry)`, creating a Merkle-like chain. If any entry is removed or modified, the hash chain breaks on the next read.

I considered using a proper Merkle tree (like Certificate Transparency logs) but it adds complexity with no practical benefit here. The audit log isn't distributed — it lives on one node. Sequential hash chaining is sufficient and simpler to verify.

The other reason for hash chaining: SIEM correlation. When the log forwards to Splunk or Sentinel, the receiving SIEM can independently verify chain integrity. If an attacker compromises the gateway node and tries to delete evidence of their tool-call injection, the SIEM's copy has the hash chain and the gap is immediately visible. I've seen this exact scenario in incident response — attacker pivots to the logging host and truncates logs. Hash chains make that detectable even if you only have the remote copy.

## Why Allow / Block / Redact / Quarantine instead of just Allow / Block?

Block is binary and often too aggressive. Real-world examples:

- An agent wants to send an email. The email body contains a customer's phone number (PII). **Redact** removes the phone number and lets the email send. Blocking the entire operation is worse for the user.
- An agent calls a tool with suspicious arguments that might be injection but might be legitimate (confidence 0.65). **Quarantine** holds the request for human review instead of silently blocking. This prevents both false-positive breakage and silent attacks.

I didn't have Redact or Quarantine in the first version. After running against real tool-call patterns from internal testing, pure Allow/Block caused either too many false positives (blocking legitimate requests with PII) or too many false negatives (allowing borderline injection). Four decisions covers the actual decision space.

## Why not hook into the MCP SDK directly?

The MCP Python SDK has transport hooks. I could have built this as an SDK middleware. I didn't because:

1. The SDK changes frequently — pre-1.0, breaking changes on minor versions.
2. Lock-in to Python. The proxy speaks JSON-RPC over stdio — it works with any MCP client in any language.
3. The SDK hook approach means the gateway runs inside the agent's process. See "Why a proxy at all?" above.

## What I'd change with more time

- **Layer 4 should support pluggable rule backends.** Right now, rules are hardcoded Python. A YAML rule DSL would let security teams add rules without touching code.
- **The circuit breaker is too simple.** 5 consecutive errors → fail open. In practice, you want different thresholds per layer, and Layer 4 errors (regex timeout) shouldn't trigger the same circuit as Layer 1 errors (network unreachable).
- **No response inspection yet.** The gateway inspects requests but not responses from tool servers. A poisoned tool server can return injection in its response that influences the agent's next action. This is the indirect injection vector and it needs a Layer 6 on the return path.
- **Shadow mode should produce diff reports.** Currently it logs "would have blocked" — it should also show what the production (non-shadow) decision was and highlight disagreements.
- **Sigma rule library needs expansion.** I have 3 detection rules for agent-specific TTPs. A production deployment needs 15-20 covering the full agent kill chain (initial access via prompt injection → tool-call abuse → credential theft → lateral movement → exfiltration). I'd also add Elastic Detection Rules format alongside Sigma for teams on the Elastic stack.
- **SOAR enrichment context.** The webhook payload sent to SOAR should include the full 5-layer decision trace, not just the blocking layer. A SOAR playbook making a revocation decision needs to know how close the request was to passing (did 4 layers say ALLOW and only egress caught it? Or did 3 layers flag it?).

## Threat model assumptions

1. The agent is untrusted — it may have been prompt-injected before making this tool call.
2. The tool server is untrusted — it may return poisoned responses.
3. The proxy itself is trusted — if an attacker controls the proxy, game over. The proxy must run in a separate security domain from the agent.
4. The configuration (rules, policies, allowlists) is trusted — it's loaded from a file at startup, not from any agent-accessible channel.
5. Network between proxy and tool server is untrusted — hence TLS pinning in Layer 1.

## References

- Greshake et al. (2023). "Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection."
- OWASP LLM Top 10 (2025 edition), particularly LLM01 and LLM07.
- MCP Specification (Anthropic, 2024) — transport layer and tools/call schema.
- Anthropic job posting: "agents holding delegated credentials, untrusted tool output crossing trust boundaries" — this is the exact problem this gateway addresses.
