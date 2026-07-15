# Command-line interface

Install from a verified source checkout during the migration:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements/ci.txt
.venv/bin/python -m pip install --no-build-isolation --no-deps -e .
.venv/bin/rigor --help
```

## Read-only inspection

`rigor scan --root PATH` inventories one Git repository and emits candidate
evidence. It does not modify the inspected repository.

Git-using commands ignore ambient `PATH` and accept a shared explicit trust
contract: `--git-executable`, repeatable `--git-trust-root`,
`--git-min-version`, and `--git-max-version-exclusive`. An absolute executable
requires an explicit containing root. Reports expose the selected Git version,
executable digest, and trust-policy digest; JSON reports additionally retain
the resolved path, selected root, and provenance identity digest.

## Evidence review

`review-template` creates explicit review records. `validate-review` verifies
that those records match the exact report. `gate` and `promote` reject stale or
mismatched state.

When policy declares native adapters, `gate` requires the explicit
`--allow-native-audits` consent flag. Adapters run in the read-only sandbox and
the resulting gate artifact binds HEAD, tree, tracked content, policy, report,
executable, command, environment, sandbox, and output digests. Raw argv and
output are not retained.

## Independent campaigns

`campaign-create`, `campaign-run`, and `campaign-compare` freeze independent
inputs, retain attestations, and record disagreements rather than averaging
them away.

`campaign-run` uses the same native consent flag and sandbox boundary. A run
without declared native adapters remains passive and does not require consent.
Native execution currently requires Linux bubblewrap at `/usr/bin/bwrap`.
Custom Git trust options used for campaign creation must be repeated for every
run. A different Git identity is reported as campaign input divergence.
`campaign-compare` accepts the same options for its Git-ignored storage check
but does not execute a new repository audit.

Run `rigor COMMAND --help` for the exact options supported by the installed
version.
