# Command-line interface

## Compatibility manifest

```console
rigor contract
```

Print the deterministic, digest-bound 1.0 Python, CLI, and
serialized-schema compatibility contract. The command reads no repository,
performs no network access, and writes no files. See the
[1.0 stable compatibility contract](stable-contract-1.0.md) for the stability,
deprecation, and migration rules. Source metadata declares `1.0.0`; the
installed command reports the version of the package actually installed.
Publication requires separate release gates and owner authorisation.

Install from a verified source checkout during the migration:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements/bootstrap.txt
.venv/bin/python -m pip install --require-hashes --no-build-isolation -r requirements/ci.txt
.venv/bin/python -m pip install --no-build-isolation --no-deps -e .
.venv/bin/rigor --help
.venv/bin/rigor --version
```

`rigor --version` prints the canonical package identity, for example
`rigor 1.0.0` for this source version, without requiring a subcommand.

The distributed GitHub Action and pre-commit hook invoke this same installed
CLI with explicit paths. They expose observe, ratchet, and zero gate modes but
do not expose `promote --apply`; see [Consumer integrations](integrations.md).

## Repeated scans in one process

Consumers that call the scanner more than once in one Python interpreter can
reuse bounded facts after parsing Python with current warning settings. Each scan reads current Git,
worktree and ignored evidence and rebuilds cross-file findings. Independent
`rigor scan` processes start with empty observation storage. See
[Repeated Python architecture scans](architecture.md#repeated-python-architecture-scans).

## Adopter preflight

Run `rigor doctor --root /path/to/repository` to check the installed package,
trusted Git, tracked policy, Bubblewrap and declared native adapter descriptors.
Use `--policy` and the Git trust options from `rigor scan` to diagnose the same
configuration. The command reads the repository and prints JSON without
creating files in it. The sandbox check runs a fixed no-op inside the normal
native isolation boundary. Repository-declared adapter commands are not run.

Each check reports its status, whether it is required, and an observation or
remediation. An unavailable Git inventory leaves policy and sandbox checks
unassessed. A missing tracked policy is reported even when the scanner can use
portable defaults. The exit status is 1 if any required prerequisite is
unresolved and 0 otherwise. Sandbox availability is required when the tracked
policy declares a required native adapter. Descriptor readiness covers local
resolution and tracked inputs. Actual audit execution produces its own evidence.

## Explicit output files

Explicit output paths must be new files below existing directories. Existing
files and symbolic links are refused without overwriting their contents.
Invalid UTF-8 is refused before creating an output file.

On POSIX, an interrupted or failed write can leave an empty or partial file.
The command still fails; file existence alone does not prove that a report is
complete. Inspect retained files before removing them, and use a new filename
for a retry. Failure cleanup preserves directory entries because another
process may have replaced the original output. On Windows, the native writer
can discard its own created object through the retained file handle.

## Conditions with partial observations

The provisional module command
`python -m rigor_foundry.condition_evaluation_cli --expression expression.json
--observations observations.json` evaluates the existing condition language over
explicit known, absent and unknown observations. It returns distinct true,
false and unknown states and never grants effects. See
[Conditions with partial observations](condition-evaluation.md) for the exact
operand/result versions, input restrictions and exit codes. This separately
versioned module command does not change the frozen `rigor`1.0 inventory.

## External source provenance

`source-capture` records already-retained HTTPS response bytes under an exact
retrieval policy. It does not perform or authorise network access.
`source-verify` deterministically verifies one advisory, version, standard, or
content-digest claim against the exact capture and payload. See
[Verified external source provenance](source-provenance.md) for the complete
contract and examples.

`scan-provenance` runs the static scan and attaches a separate record for
hash-locked distribution attestations and source-bound Scorecard checks.
It uses a local profile whose SHA-256 you supply independently. Install the
`provenance` extra to verify PyPI Publish and SLSA signatures. A successful
command writes both the audit report and the individual evidence outcomes.
See [offline dependency provenance](source-provenance.md#offline-scan-with-signed-distribution-evidence)
for the profile fields and command example.

## Offline evidence verification

`rigor verify --bundle BUNDLE.json --trust-policy TRUST.json --at TIMESTAMP
[--output RESULT.json]` verifies signed reports, review attestations,
StandardPacks, model-alias collapse, key lifecycle, expiry, and explicit
unavailable evidence using only local supplied bytes. The separate trust
policy is caller-selected and cannot be replaced from inside the evidence
bundle. `--at` is mandatory UTC so the result is deterministic.

Exit status is zero only when every entry verifies, one for a parseable
invalid/stale/unavailable result, and two for malformed or unsafe input. See
[Offline evidence verification](offline-verification.md) for schemas,
signature domains, input restrictions, and the assurance boundary.

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

## Offline CRA preparation

`cra-bootstrap`, `vuln-register`, `vuln-timeline`, `cra-draft`, `cra-receipt`,
`cra-skip`, `user-notice`, and `cra-status` implement the prepare-only CRA
reporting workflow. `sbom-import` and `sbom-status` add imported-inventory and exact
Git-drift evidence. The explicit OCI SPDX profile binds an original in-toto
statement to the selected image manifest and reads its directly contained
packages. See [OCI image statements](cra-reporting.md#import-an-oci-image-statement).
`vuln-register` accepts a complete content-bound offline
OSV adapter bundle as awareness evidence, but still requires separate explicit
active-exploitation evidence. The commands retain append-only evidence below
`.rigor/cra/` and contain no network client. A receipt binds operator-supplied
evidence after an external manufacturer action; it does not prove submission
or authority acceptance.
`advisory-draft`, `advisory-publish`, and `advisory-delay` add append-only
fixed-vulnerability advisory evidence without publishing. Publication and
delay evidence remains under the repository root because replay binds its
relative path and current bytes. `cra-pack` emits the fixed CRA StandardPack
using a caller-supplied Ed25519 signing key; the key is never retained. Policy
schema 1.4 explicitly activates CR001–CR006, while schema 1.3 and
absent/not-applicable CRA blocks remain inert.
See [Offline CRA Article 14 preparation](cra-reporting.md) for exact commands,
deadline semantics, payload partitions, exit codes, and legal-claims boundary.
See [CRA readiness rules and StandardPack](cra-rules.md) for policy activation,
rule verification, pack signing, campaign integration, and the enforcement
prohibition.

## Check a repository policy

```bash
rigor policy-check --root . --policy config/draft-policy.json
```

The default input is `rigor-foundry-policy.json` under the declared root. The
provisional command accepts a draft as well as a tracked policy. It reads a
single regular file under that root without following symbolic links and
bounds the document to one MiB and 32 levels of nesting.

A valid input prints `policy check: PASS` and returns 0. A defective input
returns 1 and prints each independently diagnosable issue on its own line.
Each line starts with an escaped JSON Pointer, followed by the problem and
a fix hint. For example:

```text
"/native_audits/0/target_paths/1" Invalid repository-relative target. List unique, exact repository-relative targets appropriate to this profile.
```

Pointer indices start at zero. The empty pointer identifies a document-level
failure, such as invalid JSON. The command reports precise member names for
missing or unexpected fields, checks supported policy and adapter variants,
and locates conflicts such as a required CRA state bound to the wrong ignored
path. It omits supplied values from diagnostics. Refused input paths and
unreadable or oversized files return 2.

This is a read-only check. It validates declarations with adapter execution,
policy installation, enforcement and review authority left to their existing
entry points.

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
1.2. JSON never includes ignored file content, link targets, environment
values, or recursive directory members. `missing` and `unavailable` remain
evidence states and do not create findings by themselves.

### Exact historical revision

Use `rigor scan-revision --root PATH FULL_COMMIT_ID` to inspect an exact
local commit, including SHA-256 Git repositories. The argument must be the
full SHA-1 or SHA-256 commit object ID. The scanner reads the local Git object
store from a temporary checkout outside the source repository. It verifies the
tracked bytes against Git and removes the checkout before writing the report.
The report gives the source repository path, the selected commit and tree, and
the detached state. Current worktree changes, Git tags and branch movement do
not substitute for the selected object.

The historical tree supplies its own tracked policy. Declarations of ignored
paths are validated against that tree's Git ignore rules. Their observations
are unavailable with reason `historical-state-unavailable`, since Git does not
record their contents. The JSON, Markdown and candidate gate options apply to
the historical report. The provisional command has its own CLI contract. The
stable `scan --changed-since` entry keeps its original options.

### Incremental changed-file view

`rigor scan --changed-since REF` restricts the reported and gated candidates to
files changed between the Git revision `REF` and `HEAD`. The full deterministic
report is still computed (`--json-out`/`--markdown-out` write the complete
report); `--changed-since` prints a summary — the number of candidates in changed
files, the total, the changed-file count, and the full report digest — followed by
those candidates, and makes `--fail-on-candidates` gate only on the changed set.
This lets a pull-request or pre-commit check fail only when the changed code
introduces a candidate, without hiding the full-tree report. `REF` is validated
as a plain Git revision (a leading dash can never reach Git as a flag), and the
diff runs through the same trusted, provenance-bound Git executable as the scan.

## SARIF export

`rigor sarif --report REPORT [--review REVIEWS] [--output RESULTS.sarif]
[--profile github-code-scanning]` verifies the report and optional review ledger
before emitting deterministic SARIF 2.1.0. Without `--output`, JSON is written to
stdout. An explicit output parent must already exist. The default export is
read-only and includes every candidate. `--profile github-code-scanning` emits
only reviewed `valid` results, declares what it omitted, and refuses GitHub's
upload limits before writing anything; see [SARIF export](sarif.md) for the state
mapping, the anchor contract and the profile.

## Third-party SARIF import (provisional)

`rigor import-sarif --sarif FILE --producer {codeql,semgrep,trivy} --root CHECKOUT
--output REPORT.json [--head OID] [--checkout-root PATH] [--require-all-anchored]`
imports one declared producer's SARIF 2.1.0 file into a separate import report.
The file is refused as a whole if it exceeds a whole-file limit, comes from an
undeclared producer or from RigorFoundry itself, or describes another commit.
`--head` is required when any run states no `revisionId`. Each result becomes
an `unreviewed` candidate anchored to a clean tracked blob of the checkout, an
observation, or a skip with its reason. `--require-all-anchored` exits 1 after
writing the report when any result was skipped. The audit report, the rule
registry and the SARIF export never change; see
[Third-party SARIF import](sarif.md#third-party-sarif-import).

## Content-addressed report differences

`rigor report-diff --before BEFORE.json --after AFTER.json [--output DIFF.json]`
loads and verifies both historical reports, partitions exact candidate
identities into retained, appeared, resolved, and anchor-changed classes, and
binds the result to both report digests. Missing history fails with status 2;
it is never treated as an empty report.

Repository, branch, policy, rule-pack, or scanner changes require the matching
`--declare-*-change` flag and one `--justification`. Superfluous declarations
also fail. Ambiguous relocation can be represented only through a strict
`--anchor-matches` JSON document with exact before/after candidate IDs and a
retained rationale. See [Content-addressed report differences](report-diff.md)
for the schema, replay contract, and non-verdict boundary.

## OSCAL export (candidate evidence only)

`rigor oscal --lock LOCK.json --assessments ASSESSMENTS.json --template TEMPLATE_ID
--generated-at TIMESTAMP [--output RESULTS.oscal.json]` loads a serialised
effective-profile lock and a JSON array of per-control assessments, maps them
through a built-in evidence-map template, and emits deterministic OSCAL 1.1.3
assessment-results JSON. The export is triage-only: it is **not** a certification
or attestation, omits findings and risks, requires an explicit UTC
`--generated-at` (no wall clock), and points `import-ap` at the documented
export boundary. Built-in template ids are listed in
[Compliance evidence maps](compliance-maps.md). Without `--output`, JSON is
written to stdout; an explicit output parent must already exist and the path
must be created exclusively.

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
Built-in profiles use the same consent flag and emit structured fail-closed
evidence; see [Built-in adapter profiles](adapter-profiles.md).

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
also requires repository policy schema 1.3 to bind the maturity report's exact
`policy_digest` as `maturity_policy_digest`. It binds both the maturity-policy
and maturity-report digests, counts active and probationary candidates
separately, and lists every probationary rule present in the current report.
Probationary candidates cannot block and cannot be omitted from the artifact.
Observe mode may run without a maturity report and makes no rule-activation
claim. A command-line mode cannot supply an unbound calibration policy while
strengthening repository enforcement.

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

Campaign schema 1.9 freezes the repository Git object format and ignored
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
search match. The command prints a fixed pass or fail status. Trusted callers
can obtain the detailed findings from the Python validator. The focused owner
tests and remote coverage matrix supply the measured coverage evidence.

Run `rigor COMMAND --help` for the exact options supported by the installed
version.
