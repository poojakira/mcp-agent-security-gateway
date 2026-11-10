# Public/private separation guide

This public repository is source-visible. The following **future** material should not be added here: unreleased commercial product modules, customer configurations, sensitive bypass-resistant implementation details, signing keys, credentials, exploit reports awaiting coordinated disclosure, and unpublished research partner data.

## Private split procedure
1. Inventory candidate components and ensure ownership and dependency licenses permit relocation.
2. Create a separate private repository under an owner-controlled account; do not import third-party research code without authorization.
3. Add least-privilege collaborators only as needed. Enable MFA, branch protections, required approvals, and secret-scanning capabilities available to the account.
4. Create a narrow documented interface to the public gateway; keep the public gateway functional without the optional private extension.
5. Verify package boundaries, import paths, tests, CI and reproducibility before publishing any public interface.
6. Audit Git history, released artifacts, documentation and forks for historical exposure. Moving or deleting does **not** make previously public content confidential or revoke earlier permissions.
7. Keep the ontology-specific collaboration implementation separately licensed, with documented background/foreground IP ownership.

**This document does not itself hide any code or change access permissions.** GitHub visibility must be configured for the repository holding the material. Never commit secrets to either repository.
