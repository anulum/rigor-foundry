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

JSON report schema 1.3 records `git_object_format`, the declared ignored-path
evidence tuple and digest, and a strict discriminated
anchor for every candidate. `tracked-blob` anchors include path, inclusive
`line_start`/`line_end`, exact scanned `blob_oid`, and `content_sha256`.
`repository-tree` anchors include the path locus, fixed `1:1` state span,
`tree_oid`, and `tracked_content_sha256`. Markdown output renders the same
location, anchor kind, object identity, and digest beside the bounded evidence
excerpt.

Ignored evidence is collected only for exact paths declared by policy schema
1.1. JSON never includes ignored file content, link targets, environment
values, or recursive directory members. `missing` and `unavailable` remain
evidence states and do not create findings by themselves.

## Evidence review

`review-template` creates explicit review records. `validate-review` verifies
that those records match the exact report. `gate` and `promote` reject stale or
mismatched state.

When policy declares native adapters, `gate` requires the explicit
`--allow-native-audits` consent flag. Adapters run in the read-only sandbox and
the resulting gate artifact binds HEAD, tree, tracked content, policy, report,
executable, command, environment, sandbox, and output digests. Raw argv and
output are not retained. The structured sandbox evidence records the complete
Bubblewrap compatibility policy, semantic version, binary digest, Debian
package version/architecture/status, package-query binary digest, supported
option-surface digest, and derived provenance identity.

## Independent campaigns

`campaign-create`, `campaign-run`, and `campaign-compare` freeze independent
inputs, retain attestations, and record disagreements rather than averaging
them away. `campaign-create --purpose promotion` defaults to two required model
witnesses; `--required-model-witnesses` may raise that threshold.

Campaign schema 1.6 freezes the repository Git object format and ignored
inventory in addition to the report input projection. Every `campaign-run`
requires `--provider`, `--model`, `--model-family`, and `--operator`. The exact
identity is content-addressed in the run attestation. Runs from a different
object format or ignored state fail as input divergence. Evidence is collected
again after native adapters; any mutation rejects the run before attestation.

`campaign-run` uses the same native consent flag and sandbox boundary. A run
without declared native adapters remains passive and does not require consent.
Native execution currently requires Debian-family Bubblewrap 0.9.x at
`/usr/bin/bwrap`, with an installed `bubblewrap` association reported by
`/usr/bin/dpkg-query`. That database association is not a repository-signature
or payload-checksum proof; the executable SHA-256 records the actual binary
identity. Missing or changed provenance fails closed.
Custom Git trust options used for campaign creation must be repeated for every
run. A different Git identity is reported as campaign input divergence.
`campaign-compare` accepts the same options for its Git-ignored storage check
but does not execute a new repository audit. Runs sharing one model-family
value collapse to one witness. Promotion requires an otherwise resolved
promotion comparison with at least two model-family witnesses and two operator
identities.

`rigor promote` requires both `--campaign` and `--comparison`. It reloads the
durable campaign, runs, reports, and reviews, reconstructs the comparison, and
requires the selected report and review to be members of that exact eligible
comparison before applying the usual current-tree and explicit-write checks.

## Classified residual validation

`rigor residuals-check --root PATH` validates the repository-relative
`coverage-residuals.json` manifest. `--manifest` selects another
repository-relative manifest when a repository adopts the same contract.

The command rejects schema drift, duplicate or unsorted identifiers, source
symbol or guard drift, stale symbol digests, missing public verification tests,
review dates in the future, expired reviews, and any preregistered negative
search match. It does not mark residual lines as covered and does not execute
the cited tests; the focused owner tests and remote coverage matrix remain
separate required evidence.

Run `rigor COMMAND --help` for the exact options supported by the installed
version.
