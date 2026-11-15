# EPS D2 license and acceptance register (DRAFT — not an authorization)

## Licensing status
The repository root LICENSE is proprietary. No existing written authorization to David to
execute the current owner-controlled gateway on Node1 has been verified. Prior MIT grants
remain valid for material released under those grants. This document does **not** grant
permission or modify the root LICENSE.

## Proposed separate authorization for owner signature
Rights holder: Pooja Kiran.
Proposed recipient: David (full legal name and organization to be confirmed).
Machine: Node1 (operator, physical/cloud ownership and security boundary to be confirmed).
Purpose: run a designated pinned version of the MCP Agent Security Gateway for the
EPS D2 controlled experiment, including local tests and evaluation only.
Permitted: execute and make necessary internal copies for that purpose, subject to
third-party rights. Not permitted without additional written permission:
redistribution, sublicensing, public hosting, commercial reuse or training.
Duration, governing terms, security responsibilities, artifact version and
effective date: to be agreed and signed in writing.
Status: PENDING OWNER SIGNATURE AND RECIPIENT CONFIRMATION.

## Architecture and limitation
D2 must run as a separate process outside model and harness. The provided
`eps_d2.py` module is a policy engine, not yet a network service or mandatory
Node1 deployment. Harness cannot be considered isolated until OS/container
permissions prevent direct downstream tool access. Every instruction delivery
and tool call must use a D2 enforcement endpoint; deny on timeout/error.

## Proposed vocabulary for Eric to approve
kind: instruction | tool_call
act_type (PROPOSAL ONLY): read | write | delete | send | execute | disclose | delegate
tool (PROPOSAL ONLY): stub.read | stub.write | stub.delete | stub.send
Do not treat these names as Eric-approved.

## Canonical acceptance (NOT EXECUTED)
Expected: 1 ALLOW, 2 ALLOW, 3 BLOCK, 4 ALLOW, 5 BLOCK,
6 BLOCK, 7 BLOCK, 8 TBD by frozen answer key, 9 ALLOW.
Do not fabricate event inputs or decisions. Required before acceptance:
Eric's signed/frozen rule table, nine event payloads, answer key,
identity/authority mapping, precedence semantics, and version hash.
For each event record proposal, D2 rule and decision, and actual stub state
before/after. All BLOCK/ESCALATE cases must have unchanged protected state.

## Additional release blockers
- No verified Node1 deployment or non-bypassability
- No independent network D2 service or delivered-instruction adapter
- No evidence of David's written authorization
- No canonical 1–9 execution evidence
- No CI run of new module on branch yet
