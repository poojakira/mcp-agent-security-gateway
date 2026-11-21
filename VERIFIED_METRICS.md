# Verification snapshots

Metrics belong to the source and environment that produced them. **No fresh execution is claimed for the documentation-reconciliation head until its own manifest exists.** Full-contract release status remains PARTIAL.

## Last published implementation-source result

| Field | Recorded value |
|---|---|
| Source | `4b6bb486d83f4410037113e64848a22e4a06f713` |
| Full local regression | 829 passed, zero skipped/failures/errors |
| Statement coverage | 81.80446084185813%; unchanged 77% gate |
| Independent focused review | Passed at that source; narrower than a separate full-suite run |
| Hosted workflows | Six source-associated workflows succeeded, including container build/runtime smoke |
| Manifest and command/environment detail | [Published manifest](https://github.com/poojakira/mcp-agent-security-gateway/blob/d0d78a97802b203a9652b7fceb50acc0711a66e1/release-evidence/manifest.json) |
| Assessment and residual risk | [Published assessment](https://github.com/poojakira/mcp-agent-security-gateway/blob/d0d78a97802b203a9652b7fceb50acc0711a66e1/release-evidence/RELEASE_ASSESSMENT.md) |

These are prior implementation-source results, not a claim that a later documentation commit ran the same tests. Coverage is a code-execution measure, not detector efficacy. Separate runs/environments must not be summed into a new test total. See [docs/EVIDENCE.md](docs/EVIDENCE.md) for the pending exact-new-head archive and reproduction procedure.

## Historical snapshots

The October 13, 2026 hosted Linux Python 3.12.15 run [38462601803](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/38462601803), source `c75c52db`, recorded 782 passed and 81.93% statement coverage (5,657 statements, 1,022 missed). Its Windows counterpart recorded 81.47% at `b6d7122`; platform differences must stay explicit. Neither snapshot attests to the later workbench implementation.

The earlier 723/81.91%/55-signature snapshot at `008775c8878cc70c50247baa223da3256e093316` is preserved in [the historical archive](docs/archive/HISTORICAL_EVIDENCE.md). Poster/application snapshots retain their own source/date bounds. A signature/rule inventory, curated fixture result, test count and production impact are different claims.
