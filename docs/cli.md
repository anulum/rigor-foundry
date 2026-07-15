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

Run `rigor COMMAND --help` for the exact options supported by the installed
version.
