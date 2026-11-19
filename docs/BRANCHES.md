# Selected branches and recovery

The owner requested that only selected branches remain. The selected set is `main` plus `codex/local-workbench-20261116`, independently in this repository. Main is the unchanged protected default; the candidate contains reviewed local-product/documentation work in PR #194. This selection is not a production release approval.

## Retired branches

6 additional branches were retired in this cleanup. Every exact tip is retained in an annotated `archive/selected-20261118/ORIGINAL_BRANCH` tag, whose remote peeled SHA was verified before conditional, atomic branch deletion. A private Git bundle was verified before mutation. Active dependency proposals were retired without merging their unreviewed changes; unique experimental work is preserved by its recovery ref rather than silently discarded. Historical deployment refs were checked and preserved. Private bundles are not public evidence.

Read the generated [branch-cleanup record](https://github.com/poojakira/mcp-agent-security-gateway/tree/evidence/selected-branches-20261118/release-evidence/branch-cleanup.json) for exact names, SHAs, unique-commit counts, affected PRs, commands/results and recovery tags. Earlier cleanup records retain their original dates/source scope. The count above is this cleanup's count, not every historical deletion.

## Restore a retired branch

Inspect the exact record first, then restore its original SHA under its original name:

```sh
git fetch origin --tags
git push origin EXACT_RECORDED_SHA:refs/heads/ORIGINAL_BRANCH
```

These are placeholders, not commands to copy without selecting the record. Restore does not merge it, approve its dependencies or rerun its old CI. New source needs fresh verification. Recovery tags are non-release archives. Do not force-move them or rewrite shared history.

## Future automation

GitHub dependency/security automation remains enabled. No security check or branch-protection requirement was disabled to reduce the branch count. A bot or contributor may create a new branch later; retire it only after preserving/reviewing its tip and references. The final report records a timestamped branch inventory, not an enforceable promise that no actor can create another branch.
