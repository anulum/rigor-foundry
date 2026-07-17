# Validation

Local development is deliberately resource-bounded. Run the static checks and
the focused test file that owns the changed production surface:

```bash
make lint
make typecheck
make bandit
make audit
make test-file TEST=tests/test_name.py
```

The exhaustive suite, aggregate branch-coverage threshold, Python 3.11–3.13
matrix, CodeQL, and OpenSSF Scorecard remain remote gates. A release-candidate
local closeout may additionally run the hash-locked dependency audit, Semgrep,
package installation smoke, hardened container smoke, and strict documentation
build; those local results do not replace the corresponding remote evidence.

Property assurance uses the hash-locked Hypothesis dependency through public
production APIs. Dedicated owners cover strict protocol parsing, canonical
serialization and digests, bounded condition evaluation, repository-relative
path confinement, digest-dependency graph validation, and rule-registry
invariants. Each strategy has bounded examples and no timing deadline. A found
counterexample must be reduced to a named deterministic regression before the
fix is accepted; generated examples supplement those regressions rather than
serving as generic coverage input. Tests must not call private production
helpers or replace production results with mocks.

Strict-parser properties cover repository policy plus representative nested
and top-level project intent, project profile, evidence contract, control
definition, and work-task records. Every top-level field is mandatory and an
unknown field fails before digest comparison. Condition schema 1.1 is the
bool-safe evaluator contract; schema 1.0 expressions are rejected rather than
silently reinterpreted.

The quality job also scans the clean checkout with
`rigor-foundry-policy.json`, runs every full-scope native control in observe
mode, and retains the report, Markdown rendering, and gate record for 30 days.
Observe mode preserves candidate evidence without misrepresenting static
signals as reviewed defect verdicts.

Built-in adapter-profile owners execute real Semgrep and Trivy binaries through
the public descriptor-bound Bubblewrap boundary. They cover strict policy and
output schemas, clean/findings/partial/unavailable relations, tracked-only
snapshot construction, linked/oversized/dirty/drifting inputs, durable campaign
round trips, missing executables, and exact version/config/input/output
identity. CI installs Trivy only after the pinned checksum-list and archive
digests are both verified. The focused benchmark records non-isolated wall time
for both profiles; it is evidence about orchestration overhead, not a
throughput or cross-language implementation claim.

The focused SARIF owner scans real Git repositories and exercises the public
API and subprocess CLI. It covers every review-state mapping, exact anchors,
stable identifiers, URI encoding, fail-closed invalid reviews, deterministic
round trips, and 100% branch-aware isolated exporter coverage. Distribution CI
also scans and exports through the installed wheel outside the checkout, then
validates the result against the SHA-256-pinned official OASIS Errata 01 schema.

Rule-maturity validation has dedicated protocol and CLI owners. The protocol
owner reaches 100% statement and branch coverage across threshold validation,
source-bound evidence, conservative median and nearest-rank p90 calculations,
finite probation reasons, complete-pack assessment, strict parsing, duplicate
rejection, and digest recomputation. The CLI owner scans a real Git repository,
builds and adjudicates a real review ledger, evaluates an explicit case
manifest, and proves that ratchet requires the exact repository-bound maturity artifact while
keeping probationary candidates visible and non-blocking.

Candidate anchors have a dedicated real-repository contract. The focused owner
tests cover clean, unstaged, and staged-plus-unstaged bytes; text, binary,
non-UTF-8, symlink, oversized, missing, and gitlink paths; SHA-1 and SHA-256
repositories; alternate policy discovery; inclusive AST spans; negative-search
tree anchors; bounded large-member evidence; strict schema parsing; report
round trips; concurrent oversized-file mutation rejection through public
inventory and scan APIs; dangling-symlink rejection; deleted registered-owner
tree anchoring; and anchor drift rejection. The candidate-anchor module must
retain at least 95% branch-aware isolated coverage.

Module-size governance is checked against the real repository inventory. The
registered path sequence must be sorted and unique, equal the complete current
large-owner candidate set, and produce no missing, invalid, incomplete, or
line-drift candidate. This makes dependency/reassessment evidence durable
without misrepresenting a line-count signal as an automatic GodFile verdict.

Language-capability tests assert the exact scope, responsibility, and polyglot
suffix projections; dependency parser and resolution order; nested and
overlapping roots; prefix-collision rejection; case-normalised test naming;
polyglot-only plural native tests; and resolved filesystem containment. A real
multi-language Git fixture pins the complete `(rule_id, path, candidate_id)`
tuple digest captured before registry wiring, preventing a classifier refactor
from silently changing candidate identity. YAML remains scope-only and Python
never enters non-Python ownership analysis.

The Git provenance owner tests use real executable files and temporary Git
repositories. They cover fixed-root selection under hostile `PATH`, symlinked
roots and executables, post-capture replacement, unsupported versions, durable
report/campaign binding, filesystem-monitor suppression, reserved hook-path
rejection, CLI configuration, and campaign divergence. These focused tests do
not replace the hosted Python-version matrix.

External source-provenance tests use real retained files through no-follow,
single-link stable reads. They cover advisory, version, standard, and digest
claims; duplicate JSON keys; JSON Pointer escapes and arrays; policy, URI,
capture, freshness, verified-value type, digest-recomputed cross-record
contradictions, and digest divergence; CLI capture-to-verification; public
imports; and normative digest propagation. The distribution job builds a wheel,
installs it into a fresh virtual environment, changes into a temporary directory
outside the checkout, and executes the installed `rigor source-capture` then
`rigor source-verify` console-script boundary against real retained bytes.

Security-sensitive tests must exercise public APIs with real processes,
filesystems, and installed platform surfaces. The quality job runs
`rigor residuals-check --root .` to reject private production-helper calls,
`object.__new__` construction, monkeypatched production internals, stale source
bindings, missing public regressions, and expired residual reviews. Classified
race, platform, and runtime-invariant residuals remain visible debt and receive
no coverage credit.

Ignored-inventory validation uses real temporary Git repositories. The focused
owner test covers strict declarations, tracked and nonignored rejection,
regular files, directories, missing paths, final symlinks, unsafe symlinked
parents, report round trips, sentinel non-disclosure, and five deterministic
inotify-synchronised concurrent-mutation runs. Campaign and promotion tests
prove ignored-state drift is rejected before attestation or TODO mutation.

Campaign identity tests cover strict provider, exact-model, correlation-family,
and operator schemas plus transitive same-family or exact-model witness
collapse. Comparison parser regressions recompute witness and comparison
digests after introducing cross-component family or exact-model overlap and
prove that the durable record still fails closed.
Workflow, comparison, storage, promotion, and installed-CLI tests use real
repositories and durable records to prove cross-model eligibility, same-family
rejection, operator separation, exact report/review membership, replay and
tamper rejection, storage-link safety, and concurrent tracked mutation
rejection.
Campaign storage tests also reject symlinked run directories, linked
attestations, hard-linked reports and reviews, and symlinked campaign-parent
components through the public durable-loading APIs.

Release eligibility additionally requires exact-version metadata, wheel and
source-distribution checks, hashes, SBOM evidence, signatures, provenance, an
independent audit, and explicit owner authorisation. The exact-tag guard uses
only the Python standard library and is tested through an isolated `python -S`
process, so release, container, and package-publication jobs can execute it
before installing the project package.

The built-wheel metadata guard runs in CI, tagged release assembly, and PyPI
publication. It checks the real wheel's name and version, requires a
version-matched installation command plus the public registry link, and rejects
status text that publication would contradict. Automated package publication
uses the repository owner actor; an explicitly confirmed owner-only dispatch is
available for recovery from the named tag or the repository default branch,
always checks out its fully qualified tag ref, and first verifies an existing
published GitHub Release. The publication job's write permission is limited to
attaching Sigstore bundles to that release. The signing action's native release
uploader is disabled because its upload set includes signed inputs and source
archives. Both paths require exactly two generated package bundles, move them
out of the distribution directory, and revalidate the wheel and source
distribution before attestation and publication. One repository-controlled
upload attaches only those two bundle paths. Checkout credentials are not
persisted. The PyPI environment normally admits only `v*` tags; default-branch
recovery uses a time-bounded `main` deployment policy that is removed after the
run. Required owner review remains active. See the repository
[validation matrix](https://github.com/anulum/rigor-foundry/blob/main/VALIDATION.md).

CI-facing repository guards and the composed self-audit print only fixed
pass/fail status, so their diagnostics cannot disclose credential-bearing
filenames, expose broken-link paths through tracebacks, or inject forged log
lines. Trusted in-process secret findings retain full SHA-256 path identifiers
without candidate values. Third-party analyser output follows the analyser's
own reporting contract.
