# Research collaboration and proprietary boundaries (proposed)

> **Status: proposed policy, not an executed agreement or access control.** This document supplements, and does not replace, [LICENSE](../LICENSE). It grants no permissions by itself. Written authorization must be signed by the applicable rights holders before collaborators use proprietary material beyond existing rights.

## Scope
The MCP Agent Security Gateway is an independently maintained, source-visible proprietary project. The planned ontology-governed agents study may evaluate its integration with EPS Astro-RAG and Web4/Hestia, but the research collaboration does **not** automatically transfer ownership of the gateway, grant commercial distribution rights, or establish a new joint company.

## Ownership boundary
- **Background IP**: Each party retains its independently developed source code, documentation, methods, know-how, datasets and pre-existing licenses. This repository's owner retains her rights in the original gateway subject to applicable law, existing third-party rights and valid prior grants.
- **Foreground improvements**: Ownership of work created during the study must be agreed *before* contributions are merged. For each change, record author(s), affected repository, license/assignment and whether reuse outside the study is permitted. Do not assume that a pull request transfers copyright.
- **Integration artifacts**: Prefer independent adapters/interfaces and separate repositories for Astro-RAG-specific ontology modules, data, research harnesses and benchmark fixtures. Make their license and ownership explicit.

## Default collaboration posture
- No collaborator receives write/admin access, deployment credentials, production data, or GitHub secrets by default.
- No one may redistribute, relicense, sublicense, publish proprietary source excerpts, or deploy this software for third-party commercial services without separate written authorization, except as permitted by law, valid earlier license grants, or GitHub's applicable terms.
- Research permissions, if agreed, should identify authorized persons/institutions, exact versions, duration, permitted tests, compute environments, publication review process, permitted derivative works, data handling, termination and commercial-rights exclusions.
- Security findings may be responsibly disclosed via [SECURITY.md](../SECURITY.md). Do not publish real credentials, private keys, access tokens, internal endpoints, private datasets, or exploit details that create an active risk.
- No external collaborator may represent the gateway as independently certified, production-approved, jointly owned, or endorsed without express approval.

## Publication and evidence
Research authors can report measured, reproducible performance and limitations under agreed publication terms. Distinguish an illustrative demo from a preregistered study. Capture version hashes, policy/ontology versions, authorized/blocked outcomes, and independent assessment limitations. Do not imply that source-visible material is open source.

## Future/private development
Roadmaps, commercialization plans, sensitive architecture, unreleased defensive techniques, private security findings, customer integrations and credentials should live in **separate private repositories or restricted services**, not in this public repository. A public GitHub repository does **not** support hiding individual tracked paths. Removing a file from the current branch does not remove it from forks, clones, cached views or Git history. Review any prior licenses before attempting changes to distribution. Do not rely on .gitignore, CODEOWNERS, README notices or a PR template to restrict public read access.

## Approval checklist (before research code access)
- [ ] Verify historical license grants, dependencies and contributor provenance.
- [ ] Sign a narrowly scoped research-use agreement with relevant parties.
- [ ] Define background IP, jointly authored changes, independently developed adapters and commercialization rights.
- [ ] Review publication, credit, confidentiality, security reporting, termination and liability provisions with counsel.
- [ ] Limit collaborator role/access and maintain branch protection, required reviews, and secret scanning in GitHub settings.
- [ ] Keep experimental operation sandbox-only until independently validated.

This is an engineering governance proposal, not legal advice or a contract.
