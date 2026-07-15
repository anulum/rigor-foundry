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
- Adversarial tests now cover exact pack proofs, strict identifiers,
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
- Hash-locked CI, build, test, and security environments installed cleanly;
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
