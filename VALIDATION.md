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
| Packaging | Wheel and sdist build; wheel smoke outside checkout | Build, Twine check, wheel smoke |
| Documentation | Strict MkDocs build | Strict build and Pages artifact |
| Container | Local build/smoke when resources permit | Non-root CLI smoke and vulnerability scan |
| Security | Bandit and dependency audit | CodeQL, pip-audit, Scorecard, secret scan |
| Repository self-audit | Immutable temporary-commit scan for authoring evidence | Full policy scan, native-control gate, and 30-day evidence artifact |
| Git provenance | Real path-shadowing, symlink, replacement, version, report, CLI, and campaign regressions | Same focused contracts plus supported Python matrix |
| Sandbox provenance | Real dpkg association/version/feature inspection, parser tampering, executable replacement, and nested-userns boundary | Ubuntu 24.04 AppArmor/package smoke plus supported Python matrix |
| Signature domains | Exact message vector, invalid domains, legacy raw signatures, schema migration, and cross-protocol replay | Same contracts plus supported Python matrix |
| Digest dependencies | Production-record mutation propagation, stable non-edges, graph schema, and strict closure tampering | Same contracts plus full supported Python matrix |

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

The digest-dependency lane ran 105 affected tests across 12 explicit owner and
consumer files without invoking the prohibited aggregate local suite. Its
51-test owner coverage run reached 99.03% branch-aware coverage across the five
changed protocol modules; the new graph, closure, and versioned-rule modules
each reached 100%. The graph mutation tests compare all 12 identities for every
declared upstream class, require every reachable digest to change, and require
every unrelated digest to remain stable. Ruff, strict MyPy, Bandit, Semgrep,
strict repository and documentation audits, Actionlint, typos, REUSE 171/171,
secret and dependency-waiver guards, and both dependency audits passed. A
fresh wheel and source distribution passed Twine checks; a clean external
environment installed the hash-locked runtime dependencies and wheel, then
reproduced the normative graph and rule-pack digest vectors through the public
API. Hosted CI remains required after an authorised push.

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
release, and publication workflows remain remote-only gates until an authorised
first push creates `main`.

The repository is public but unreleased. Container and PyPI publication remain
fail closed until the release environment has required-reviewer protection;
that configuration is a promotion gate before the first public release.

## Required promotion evidence

Promotion requires all local gates, a clean independent exact-SHA audit, green
remote workflows, no open high-severity security finding, an external-adopter
campaign with reviewed evidence, and explicit owner authorisation. A static
zero-candidate result alone cannot satisfy promotion.
