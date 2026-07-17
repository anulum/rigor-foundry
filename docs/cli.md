# Command-line interface

Install from a verified source checkout during the migration:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements/ci.txt
.venv/bin/python -m pip install --no-build-isolation --no-deps -e .
.venv/bin/rigor --help
.venv/bin/rigor --version
```

`rigor --version` prints the canonical package identity, for example
`rigor 0.1.1`, without requiring a subcommand.

## Explicit adopter bootstrap

`rigor bootstrap` creates one new trackable policy and one new Git-ignored
canonical TODO. It requires explicit `--policy`, `--todo`, `--review-ledger`,
`--source-root`, and `--test-root` values and never guesses or overwrites them.
Parents and source/test roots must already exist without symlink components.
The TODO and review-ledger paths must already be ignored; the policy must not
be ignored or tracked. Repeat root options for multi-root repositories.

The generated observe-mode policy marks every domain required. Missing portable
or native coverage therefore remains visible until the adopter records an
evidence-backed applicability decision. See [First repository](getting-started.md)
for the complete workflow and failure boundary.

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

## SARIF export

`rigor sarif --report REPORT [--review REVIEWS] [--output RESULTS.sarif]`
verifies the report and optional review ledger before emitting deterministic
SARIF 2.1.0. Without `--output`, JSON is written to stdout. An explicit output
parent must already exist. Export is read-only and includes every candidate;
see [SARIF export](sarif.md) for the state mapping and anchor contract.

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

## Rule maturity

`rigor maturity-evaluate --cases CASES.json [--output MATURITY.json]` reads an
explicit schema-1.0 case manifest. Each case names one integrity-verified report
file, one review document, an exact candidate identifier, a portable repository
identifier, measured reviewer-effort seconds, and one or more retained
effort-evidence references. Relative report and review paths resolve from the
case-manifest directory. The command selects exactly one completed review per
case and rejects stale, incomplete, duplicate, malformed, or digest-changed
records.

The manifest policy states minimum review, repository, reviewer, and positive
decision counts plus maximum false-positive basis points, median effort, and
nearest-rank 90th-percentile effort. It has no implicit default. Output covers
the complete built-in rule pack: rules that meet every threshold are `active`;
all others remain `probation` with finite reason codes. `invalid` decisions are
false positives, while `valid` and `accepted-boundary` decisions count as
positive adjudications.

`rigor gate --mode ratchet` and `--mode zero` require `--maturity`. The gate
binds the maturity digest, counts active and probationary candidates separately,
and lists every probationary rule present in the current report. Probationary
candidates cannot block and cannot be omitted from the artifact. Observe mode
may run without a maturity report and makes no rule-activation claim.

Repository and reviewer identifiers, measured duration, and effort references
are operator declarations. Schema validation and content addressing detect
unrecomputed changes; they do not authenticate those declarations. Deployments
that need authenticated calibration must add signed custody around the case
manifest and retained evidence.

## Independent campaigns

`campaign-create`, `campaign-run`, and `campaign-compare` freeze independent
inputs, retain attestations, and record disagreements rather than averaging
them away. `campaign-create --purpose promotion` defaults to two required model
witnesses; `--required-model-witnesses` may raise that threshold.

Campaign schema 1.8 freezes the repository Git object format and ignored
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
but does not execute a new repository audit. Runs sharing a model-family value
or the same provider/exact-model pair join the same transitive correlation
component and count as one witness. Promotion requires an otherwise resolved
comparison with at least two witnesses and two declared operator identities.
The operator field is auditable protocol evidence, not a cryptographic
authentication mechanism.
Each witness retains canonical provider/exact-model pairs; comparison loading
rejects a family or exact pair repeated across nominally distinct witnesses.

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
