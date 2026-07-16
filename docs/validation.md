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

The quality job also scans the clean checkout with
`rigor-foundry-policy.json`, runs every full-scope native control in observe
mode, and retains the report, Markdown rendering, and gate record for 30 days.
Observe mode preserves candidate evidence without misrepresenting static
signals as reviewed defect verdicts.

Candidate anchors have a dedicated real-repository contract. The focused owner
tests cover clean, unstaged, and staged-plus-unstaged bytes; text, binary,
non-UTF-8, symlink, oversized, missing, and gitlink paths; SHA-1 and SHA-256
repositories; alternate policy discovery; inclusive AST spans; negative-search
tree anchors; bounded large-member evidence; strict schema parsing; report
round trips; concurrent oversized-file mutation rejection through public
inventory and scan APIs; dangling-symlink rejection; deleted registered-owner
tree anchoring; and anchor drift rejection. The candidate-anchor module must
retain at least 95% branch-aware isolated coverage.

The Git provenance owner tests use real executable files and temporary Git
repositories. They cover fixed-root selection under hostile `PATH`, symlinked
roots and executables, post-capture replacement, unsupported versions, durable
report/campaign binding, filesystem-monitor suppression, reserved hook-path
rejection, CLI configuration, and campaign divergence. These focused tests do
not replace the hosted Python-version matrix.

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
and operator schemas plus deterministic same-family witness collapse.
Workflow, comparison, storage, promotion, and installed-CLI tests use real
repositories and durable records to prove cross-model eligibility, same-family
rejection, operator separation, exact report/review membership, replay and
tamper rejection, storage-link safety, and concurrent tracked mutation
rejection.

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
