# 60-Second Recruiter Demo — MCP Agent Security Gateway

This is a recording guide for a short recruiter/hiring-manager demo backed by the repository's real policy engine, tamper-evident audit implementation, and ECS formatter.

## Run it

```bash
python scripts/recruiter_demo.py
```

The demo is local and deterministic. It does **not** contact the persistent pilot, Cerberus, a customer system, or any external endpoint.

## Recording sequence

**0–10 seconds — the security boundary**

> "AI agents become a different security problem when they can act. This gateway sits between an agent and a privileged tool and makes an allow/block decision before downstream execution."

Show the repository architecture or the command about to run.

**10–25 seconds — normal call**

The script evaluates an allowlisted HTTPS destination on an allowed MCP server.

Show:

- `allowed: true`
- reason code `ALLOWED`
- downstream execution marked eligible

Say:

> "A normal tool call passes explicit server and egress policy."

**25–42 seconds — blocked SSRF-style call**

The script evaluates the same tool against `http://127.0.0.1:8080/admin`.

Show:

- `allowed: false`
- `DENY_EGRESS_NOT_ALLOWED`
- downstream execution marked blocked

Say:

> "The loopback destination is denied before it can become downstream tool execution."

**42–52 seconds — audit integrity**

Show:

- `audit_chain.intact: true`

Say:

> "The decision is written through the repository's tamper-evident audit implementation."

**52–60 seconds — SIEM-ready event**

Show:

- ECS event outcome
- risk score
- `mcp.enforcement_action: block`
- finding reason code

Say:

> "The same decision is formatted as ECS-compatible security telemetry for SIEM review."

End card:

> **MCP Agent Security Gateway**  
> Default-deny agent-to-tool security  
> 723 passing tests · 81.91% statement coverage · 9 Elastic rules · 21 SIEM tests

## Claim boundary

This demonstration proves the selected policy, audit, and ECS-formatting paths execute as shown. It is not a customer deployment, independent penetration test, universal SSRF-prevention claim, or proof that traffic bypassing the gateway is protected.
