# Validation

## Claim boundary

Local evidence verifies the recovered scanner and campaign paths, the
crash-durable work lifecycle, and the five-layer desired-state API through
strict static analysis, focused module-owned tests, immutable Git snapshots,
package installation, and a hardened container smoke. It does not prove the
full CI matrix, aggregate coverage threshold, remote security workflows,
effectiveness on external repository corpora, autonomous remediation
execution, or production promotion.

## Gate matrix

| Gate | Local policy | CI policy |
| --- | --- | --- |
| Ruff lint and format | Entire touched source/test/tool scope | Entire repository |
| Strict MyPy | Entire `src/rigor_foundry` and `tools` scope | Same scope on Python 3.12 |
| Bandit | Source and security-sensitive tools | Source and tools |
| SPDX / REUSE | Pure-Python header audit and REUSE lint | Required |
| Action pins | Every `uses:` value must be a full commit SHA | Required |
| Secrets | Worktree scan with redacted findings | Required |
| Metadata | Version, licence, Python, package, citation, and archive consistency | Required |
| Tests | Focused single test files only | Full matrix on 3.11, 3.12, 3.13 |
| Coverage | Per-module when reliable | Aggregate branch-aware gate, minimum 95% |
| Packaging | Wheel and sdist build; metadata-truth guard; wheel smoke outside checkout | Build, metadata-truth guard, Twine check, wheel smoke |
| Consumer integrations | External Git fixture; exact-source Action shell; exact-revision system hook with hash-locked executable | Local composite Action plus cloned hook at `${GITHUB_SHA}`; three retained JSON artifacts |
| Release tag | Isolated `python -S` CLI proves exact-version validation without site packages | Exact tag validation runs before build, container publication, and package publication |
| Documentation | Strict MkDocs build | Strict build and Pages artifact |
| Container | Local build/smoke when resources permit | Non-root CLI smoke and vulnerability scan |
| Security | Bandit and dependency audit | CodeQL, pip-audit, Scorecard, secret scan |
| Repository self-audit | Immutable temporary-commit scan for authoring evidence | Full policy scan, native-control gate, and 30-day evidence artifact |
| Git provenance | Real path-shadowing, symlink, replacement, version, report, CLI, and campaign regressions | Same focused contracts plus supported Python matrix |
| Candidate anchors | Real clean/dirty blob identity, line spans, tree-state absence, SHA-1/SHA-256, strict parsing, and report/CLI/TODO wiring | Same contracts plus aggregate branch-aware coverage |
| Module size | Exact large-owner set equals sorted tracked decisions; every row binds current lines, one responsibility, complete dependency boundary, and reopen trigger | Same contract plus the clean immutable repository scan |
| Ignored inventory | Real Git ignore checks, no-follow file/directory/missing/symlink evidence, concurrent mutation, campaign recollection, and promotion drift | Same contracts plus supported Python matrix |
| Sandbox provenance | Real dpkg association/version/feature inspection, parser tampering, executable replacement, and nested-userns boundary | Ubuntu 24.04 AppArmor/package smoke plus supported Python matrix |
| Signature domains | Exact message vector, invalid domains, legacy raw signatures, schema migration, and cross-protocol replay | Same contracts plus supported Python matrix |
| Digest dependencies | Production-record mutation propagation, stable non-edges, graph schema, and strict closure tampering | Same contracts plus full supported Python matrix |
| Rule maturity | Exact report/review case projection, explicit and repository-bound thresholds, conservative statistics, finite probation reasons, strict parsing, 100% isolated branch coverage, and real CLI/gate wiring | Same contracts plus aggregate branch-aware coverage and installed-wheel CLI smoke |
| Classified residuals | Exact source-symbol binding, expiry, public-test references, and preregistered negative searches | Same contract plus aggregate branch-aware coverage evidence |
| Onboarding/API stability | Real Git bootstrap, rejection of pre-existing canonical state, point-in-time ledger absence, preserved failure evidence, exact version, binding-aware export inventory, and deprecation-window tests | Installed-wheel version, binding-aware API, and real Git bootstrap/no-overwrite smoke |
| SARIF 2.1.0 | Real Git candidates, all review states, exact anchors, stable identifiers, deterministic round trip, and 100% isolated branch coverage | Installed-wheel scan/export, digest-pinned official OASIS schema validation, and aggregate branch-aware coverage |

The onboarding/API-stability owner tests execute bootstrap through real Git
repositories and filesystem objects. They require exact-path success,
second-run refusal, zero writes when canonical state already exists, preserved
incident evidence after a later failure, Git tracked/ignored separation,
symlink-parent rejection, existing source/test roots, a real outside-checkout
version command, exact `__all__` classification and runtime identities,
deterministic manifest serialization, and deprecation-window failures. Mocked
Git results or fabricated filesystem metadata are not accepted as evidence.

## Local integration evidence

On 2026-07-15:

- 42 source and tool modules passed strict MyPy.
- The complete source, test, and tool tree passed Ruff lint and format checks;
  every production source module is below the 700-line authoring threshold.
- 13 test files were run individually; 43 tests passed against real temporary
  Git repositories and the real module CLI.
- The recovered desired-state author lane passed 78 focused tests at 98.68%
  branch-aware claimed-scope coverage. An independent coordinator then ran 89
  focused tests across the ten core module owners and repeated every affected
  owner after semantic hardening.
- Adversarial tests now cover real Ed25519 pack and reviewer signatures,
  unknown keys, tampering, explicit trust-store binding, strict identifiers,
  adapter/domain evidence, applicability weakening, exact assessment-body
  attestations with distinct reviewers and keys, parent-child path conflicts,
  command-bound remediation and rollback argv, and dedicated risk-acceptance
  waivers.
- Bandit reported no issue under the documented fixed-argv process policy;
  Semgrep 1.169.0 independently reported zero findings across 42 Python
  targets for the repository's `shell=True` and dynamic-evaluation rules.
- The installed `rigor` command worked outside the source checkout.
- Fresh wheel and source distribution builds succeeded, passed Twine, and the
  wheel exposed the desired-state API outside the checkout without packaging
  tests or internal coordination files.
- Fourteen focused governance and packaging tests passed across nine
  module-owned test files.
- Hash-locked CI, build, runtime, test, and security environments installed cleanly;
  pip-audit reported no known vulnerability in the CI and test locks. The
  security-tool lock has one exact, expiring upstream-constraint exception for
  `PYSEC-2026-2132`; the allowed Semgrep scan path does not call the affected
  `click.edit` API.
- Actionlint, immutable-action, metadata, secret, typo, strict documentation,
  and REUSE 3.3 gates passed.
- The pinned-base container built from the exact Debian snapshot, ran as the
  non-root `rigor` user with a read-only root, all capabilities dropped,
  `no-new-privileges`, and a constrained tmpfs, and scanned a real host-owned
  Git repository through a read-only bind mount.
- A timeout-focused test proved that stalled preflight subprocesses terminate
  with status `124`; the fast preflight completed without invoking the
  prohibited aggregate test suite.

The final immutable prospective-tree scan and its ten required native controls
are recorded separately from this source document so their exact commit, tree,
candidate, and output digests cannot be confused with remote CI evidence.

Git executable provenance has a dedicated real-process contract. Verification
must exercise ambient `PATH` shadowing, executable and root symlinks,
post-capture replacement before attacker-byte execution, both version-interval
boundaries, POSIX and Windows record parsing, CLI trust-root configuration,
repository-configured filesystem-monitor suppression, occupied reserved hook
path rejection, report digest tampering, and campaign input divergence. Test
fixtures may use a real delegating executable, but acceptance also requires
inventory and campaign tests against actual temporary Git repositories.

On 2026-07-16, the Git-provenance owner files passed 21 tests with 100% statement
and branch coverage for `git_provenance.py`. The complete affected surface
passed 137 focused tests across 17 explicitly named files; the prohibited
aggregate local suite was not run. Ruff lint and format passed all 90 source,
test, and tool files; strict MyPy passed 46 source/tool modules; Bandit reported
no finding; Semgrep reported no finding across 46 Python targets; and the
repository audit and strict documentation build passed. Both hash-locked
dependency audits passed with only the existing machine-checked
`PYSEC-2026-2132` security-tool exception. Three packaging-contract tests, a
fresh wheel and source distribution, Twine checks, and an external wheel import
smoke also passed. Hosted CI remains required after an authorised push.

Bubblewrap provenance has a dedicated real-process contract. Repository-owned
tests must exercise the installed `/usr/bin/bwrap` and `/usr/bin/dpkg-query`,
complete policy and provenance round trips, unsupported versions and required
options, symlink/hardlink/mode/owner rejection, package-record drift, metadata
command bounds, and replacement during inspection. Adapter tests must execute
the real read-only sandbox with nested user namespaces disabled and reject provenance
changes between preflight and completed execution. Workflow regressions pin
Ubuntu 24.04, preserve global AppArmor user-namespace mediation, constrain the
profile body to `userns,`, record the dpkg association, and run a compatibility
smoke without disabling the host-wide restriction.

On 2026-07-16, 55 provenance and trusted-runner tests passed. The provenance
module reached 100% statement and branch coverage; combined provenance and
trusted-runner coverage reached 97.45%, with the trusted runner at 94%. The
complete affected surface passed 108 focused tests across nine explicitly named
files; the prohibited aggregate local suite was not run. Ruff lint and format
passed all 95 source, test, and tool files; strict MyPy passed 48 source/tool
modules. Bandit and Semgrep reported zero findings, the repository audit and
strict authoring audit passed, and the strict documentation build completed.
Actionlint, typos, REUSE (166/166), dependency-waiver, secret, and both
hash-locked dependency audits passed; the security-tool audit retained only the
existing exact `PYSEC-2026-2132` exception. A fresh wheel and source
distribution passed Twine checks, contained both provenance modules, and passed
an external installed-wheel provenance round trip with hash-locked runtime
dependencies. The exact outer-sandbox smoke succeeded and the nested-userns
probe failed as required. Hosted CI remains required after an authorised push.

Ed25519 protocol separation has a dedicated schema and replay contract. Tests
must verify the exact framed-message vector, both accepted domains, the domain
length boundary, malformed inputs, same-key cross-protocol replay, raw-digest
legacy signatures, strict envelope fields, schema migration, effective-profile
binding, and reviewer verification through the public trust boundary.

On 2026-07-16, 63 focused affected tests passed across seven explicitly named
files; the prohibited aggregate local suite was not run. A 56-test owner run
reached 98.88% branch-aware coverage across `trust.py`, `standard_pack.py`,
`review_attestation.py`, and `effective_profile.py`; the message/trust and
reviewer-attestation modules reached 100%, the standard-pack module reached
99%, and the effective-profile module reached 97%. Ruff lint and format passed
all 96 source, test, and tool files, and strict MyPy passed 48 source/tool
modules. Bandit and Semgrep reported zero findings. Repository, strict
authoring, fast preflight, Actionlint, typos, secret, dependency-waiver, and
REUSE (167/167) gates passed. Both hash-locked dependency audits passed with
only the existing exact `PYSEC-2026-2132` security-tool exception. Strict
documentation, wheel and source-distribution builds, Twine checks, and an
external installed-wheel same-key cross-domain round trip passed. Hosted CI
remains required after an authorised push.

The initial digest-dependency lane ran 105 affected tests across 12 explicit
owner and consumer files without invoking the prohibited aggregate local
suite. Its 51-test owner coverage run reached 99.03% branch-aware coverage
across the five changed protocol modules; the graph, closure, and versioned-rule
modules each reached 100%. Ruff, strict MyPy, Bandit, Semgrep, strict repository
and documentation audits, Actionlint, typos, REUSE 171/171, secret and
dependency-waiver guards, both dependency audits, package checks, and an
external installed-wheel digest round trip passed.

The current successor advances the graph to schema 1.1 and 14 identities by
adding Git provenance and toolchain nodes plus their direct bindings. Its
dedicated 13-test mutation suite reaches 100% statement and branch coverage,
requires every reachable digest to change, and requires every unrelated digest
to remain stable. Hosted CI remains required after an authorised push.

The exact-object audit of the first combined successor then identified two
blockers: campaign records did not validate the report's complete Git input at
every persistence/comparison boundary, and security-sensitive owner tests
claimed coverage through private helpers and simulated production internals.
The current successor uses one public campaign-input validator in attestation
construction, durable store/load, workflow execution, and comparison. Real
alternate Git executables now prove rejection at those public boundaries.

The same successor replaces the prohibited tests with public APIs, real
executables, real filesystems, real process deadlines, and installed-platform
contracts. Nine intentionally inaccessible fail-closed guards are instead
recorded in an expiring, source-digest-bound residual manifest. Its dedicated
32-test owner run reaches 100% statement and branch coverage for
`coverage_residuals.py`; a 138-test affected-owner invocation passed every
test. The partial combined coverage selection from that invocation is not
represented as repository-wide coverage evidence. Aggregate coverage and the
supported Python/platform matrix remain hosted-CI gates.

## Security-boundary remediation evidence

After the independent exact-SHA audit blocked the first local foundation
commit, the six accepted boundaries were remediated and retested on
2026-07-15. Ninety-four tests passed across nineteen explicitly invoked test
files; no aggregate local suite was run. Strict MyPy passed all 45 source/tool
modules, Ruff and formatting passed 87 files, Bandit reported zero findings,
and Semgrep reported zero findings across 45 Python targets.

The real native gate passed 10/10 controls inside the credential-free,
no-network, read-only bubblewrap sandbox and produced a content-addressed gate
artifact with no blockers. Runtime, CI, and test dependency audits reported no
known vulnerability; the security-tool audit reported only the one exact
machine-checked and expiring upstream Click exception. The complete preflight,
strict docs build, Apache-2.0 REUSE audit (158/158 files), wheel/sdist build,
Twine check, external wheel install, and rebuilt non-root container smoke also
passed. These remain local candidate facts until a fresh immutable commit,
third-eye clearance, independent exact-SHA audit, and public CI establish the
landing record.

The evidence is a local integration check, not the final CI or coverage record.
The full Python matrix, aggregate coverage, CodeQL, Scorecard, Trivy, Pages,
release, and publication workflows remain remote-only gates. Green `main`
workflows establish landing evidence; tag-triggered release and publication
remain separate gates.

The repository secret guard never emits candidate values or raw repository
paths. Its programmatic findings identify paths only by full SHA-256. Every
CI-facing repository guard, including the composed self-audit, emits only a
fixed pass/fail status and keeps precise diagnostics and validation exceptions
inside the process. This prevents those guard CLIs from disclosing
credential-bearing filenames, exposing broken-link paths through tracebacks, or
accepting newline-bearing paths as forged log records. Third-party analyser
output remains governed by each analyser's own reporting contract.

Version `v0.1.0` is published as a GitHub Release and GHCR image without a PyPI
counterpart. Its immutable wheel retained pre-publication-only status text, so
uploading that artefact to a permanent public index was rejected instead of
rebuilding under the same tag. Version `0.1.1` is the first PyPI-intended
release.

Release-tag validation is implemented as a standard-library-only CLI and a
real `python -S` regression proves that it runs with site-package imports
disabled and without importing the `rigor_foundry` package. A separate
distribution-metadata guard builds a real wheel, binds its name and version,
requires an exact versioned installation command and public registry link, and
rejects pre-publication status text. CI, tagged release assembly, and protected
PyPI publication all run that guard before accepting the distribution.

Automated PyPI publication gates on the repository owner as the event actor,
not on the workflow-created draft release's original author. An owner-only
manual dispatch remains a recovery path; it requires explicit public-index
confirmation, runs from either the named tag or the repository default branch,
always checks out the fully qualified `refs/tags/<name>` ref, and verifies that
the tag already has a published GitHub Release. The default-branch route permits
a workflow-only recovery after an immutable release tag exists; it never builds
package content from the branch or resolves an unqualified branch/tag name. The
publication job grants `contents: write` only so Sigstore can attach signing
bundles to that release. The pinned Sigstore action's native release uploader is
disabled because it includes signed inputs and source archives in its upload
set. Both event paths require exactly two package bundles, move them out of the
distribution directory, and revalidate that only the wheel and source
distribution reach attestation and PyPI. One repository-controlled upload then
attaches only the two validated bundle paths to the named release. Checkout
credential persistence remains disabled. The container environment accepts only
`v*` tags. The PyPI environment normally applies the same policy; default-branch
recovery requires a time-bounded `main` deployment policy that is added after
snapshotting the tag-only configuration and removed immediately after the run.
Both environments retain required owner review.

## Required promotion evidence

Promotion requires all local gates, a clean independent exact-SHA audit, green
remote workflows, no open high-severity security finding, an external-adopter
campaign with reviewed evidence, and explicit owner authorisation. A static
zero-candidate result alone cannot satisfy promotion.
