# Contributing

## Before editing

1. Read `ARCHITECTURE.md`, `VALIDATION.md`, and the public roadmap.
2. Use a fork or isolated worktree and submit a focused pull request. Maintainers
   additionally claim exact paths before editing a shared worktree.
3. Keep public product code, internal audit evidence, and adopter-specific
   findings in their defined boundaries.
4. Keep each branch and pull request limited to one coherent responsibility.

## Environment

Use Node.js 22.23.3 for the editor toolchain alongside the Python environment.
The extension runs inside VS Code's own runtime; the Node pin applies to its
development tools.

```bash
python3 -m venv .venv
make install
make install-hooks
```

The installer first installs the hash-locked source-build backends from
`requirements/bootstrap.txt`, then installs the development lock without
build isolation and the verifier profile used by the signed provenance tests.
Source distributions therefore use the admitted backends
rather than downloading a separate build environment. Native source builds
require a C/C++ compiler and the interpreter's development headers; PyYAML's
LibYAML extension also requires the LibYAML development headers and library.

## Dependency maintenance

Maintainers review dependency alerts and available versions weekly. Python
updates use an owner-controlled batch because the automated updater removes
lock-generation provenance. Regenerate affected hash locks with the pinned
`pip-tools` on Python 3.11, retain their generation commands and mandatory
metadata, and align shared versions across build, CI, runtime, security and test
inputs. The source-build bootstrap also constrains shared versions to the CI
lock; regenerate it after a CI lock update with `make lock-bootstrap`.
The security lock follows the same Python 3.11 generation contract;
its exact command is in [Security-tool lock maintenance](docs/security.md#security-tool-lock-maintenance).
Record upstream compatibility bounds when a newer release cannot be installed.
Verify the complete dependency diff and scoped checks before review;
remote CI validates the published commit. Dependency detection and alerts remain
enabled. CodeQL action steps are updated together to keep their versions equal.

Windows native tests use `requirements/test-windows.txt`, which includes the
Windows dependencies of the test environment and the complete runtime lock.
Generate it on Windows with Python 3.11 and the pinned `pip-tools` version:

```powershell
python -m piptools compile --allow-unsafe --constraint=requirements/runtime.txt --constraint=requirements/test.txt --generate-hashes --output-file=requirements/test-windows.txt --strip-extras requirements/runtime.in requirements/test.in
```

The two constraint locks retain the reviewed shared versions. Install the result
after the bootstrap using
`python -m pip install --require-hashes --no-build-isolation -r requirements/test-windows.txt`
and verify it on each supported Python version before updating the native CI
profiles.

## Quality contract

- Public Python symbols use complete typing and NumPy-convention docstrings.
- Strict MyPy and Ruff must report zero errors on touched scope.
- Editor TypeScript and JavaScript use typed ESLint, both strict TypeScript
  compiler projects, Prettier and validated TypeDoc. Every maintained editor
  runtime, test, support, launcher and tool-configuration owner has a 100%
  coverage requirement.
- Tests exercise real package, CLI, Git, filesystem, serialisation, and process
  boundaries. Mock-only claims, import-only tests, assertion-free smoke tests,
  generic coverage files, and private-helper-only tests are not accepted.
- Boundary-crossing changes include an integration or end-to-end test.
- Security suppressions are narrow, code-specific, and justified by the real
  execution boundary.
- New controls define evidence, applicability, remediation, and acceptance
  contracts; they never silently pass when unsupported.

The release metadata guard, `python -m tools.check_metadata`, binds the project,
package version, citation, archive and licence identities. Keep
`src/rigor_foundry/version.py` as an optional module docstring followed by exactly
one assignment of a string literal to the sole target `__version__`. Comments
are permitted; additional statements, repeated assignments, annotations,
computed values and additional targets are rejected. The guard parses this
source without importing or executing it. Its dedicated tests exercise copied
repository metadata and the real module command, including malformed or missing
input failures. The command prints fixed status; detailed findings remain
available through the in-process `metadata_errors` API.

Citation identity is parsed as YAML rather than extracted from text lines.
`CITATION.cff` must contain one mapping with unique string field names;
`version`, `license` and `repository-code` must have string values. YAML
comments, quoting, escapes, block strings and flow mappings preserve their
parsed meaning. Duplicate names, including equivalent escaped spellings,
invalid syntax and incorrect identity types fail validation. This checks
release identity, rather than the complete Citation File Format schema.

The separate `python -m tools.check_release_tag <tag>` guard uses only the
standard library so it can run before dependency installation. It requires a
project table with a three-component string version and an exact `v`-prefixed
tag. Invalid version values are findings; unreadable or malformed manifests
produce a fixed failure status at the CLI boundary. Trusted API callers retain
the underlying read or parse exception. Dedicated tests copy the actual guard
and complete manifest and run both normal Python and `python -S` processes.

The repository conformance audit distinguishes necessary third-party technical
names from agent identity, authorship and branding. Its conservative lexical
policy currently registers the supported native JSONL format name in explicit
format, source, transcript, message or subset context. Attribution cues in the
same paragraph take precedence; other or ambiguous names require review and an
explicit policy extension. Public fixtures use descriptive synthetic identities,
including synthetic session UUIDs, rather than actual session or seat labels.
There are no path or test-tree exceptions to this policy.

The local-only dependency guard permits explicit `urllib.parse` imports and its
documented parsing/quoting exports. It continues to reject the `urllib` root,
clients, mixed imports, wildcard or unknown exports and relative lookalikes.
This static import check complements the runtime sandbox; it does not establish
network isolation, detect arbitrary dynamic loading or validate parsed URLs.

Run focused tests locally:

```bash
.venv/bin/pytest -q tests/test_models.py
make preflight-fast
```

`make editor-check` runs the editor's complete lint, format, strict typing,
documentation and unit checks. The commit hook runs that same target; the
pre-push hook uses `make preflight-fast`, which combines Python checks with
the editor checks. These commands require the locked editor dependencies.

The full `make preflight` additionally runs native editor coverage, including
the actual single-folder and multi-root Extension Development Hosts. On a Linux machine without a display,
run `xvfb-run -a make preflight`. The direct `python -m tools.preflight` command
checks Python and repository policies; it does not execute the native editor
toolchain. See [editor verification](docs/vscode-integration.md#development-and-verification)
for the standalone commands and host requirements.

Authoring sessions reserve the exhaustive matrix for CI under fleet
resource policy. External contributors may run it locally with
`ALLOW_LOCAL_FULL_TESTS=1 make test`; the same matrix remains a required remote
gate.

## Commits and review

Commits are atomic and use Conventional Commits. Agent-assisted commits
contain exactly one vendor-neutral `Seat:` trailer and exactly one authorship
line; human and external contributor commits do not add these internal fleet
trailers:

```text
Seat: <seat-id>

Authored by Anulum Fortis & Arcane Sapience (protoscience@anulum.li)
```

In the shared worktree, the author does not push their own commit. A peer
audits the exact SHA in isolation and records the gate outcome before any push.
External contributions follow the ordinary fork and pull-request review flow.

Unless a contributor explicitly marks a submission as “Not a Contribution,”
contributions intentionally submitted for inclusion are licensed under
Apache-2.0 as described by section 5 of [LICENSE](LICENSE). No contributor
licence agreement is currently required.

## Internal material

For maintainers, coordination logs and handovers live only in the monorepo
`.coordination/{sessions,handovers}/RIGOR-FOUNDRY/`. Repository-local
`docs/internal/` is ignored and may hold non-public product audit evidence;
external contributors should not create it.
Never commit credentials, private repositories, internal plans, or audit
reports containing proprietary source excerpts.

## Workflow changes

The small [CI coordinator](.github/workflows/ci.yml) calls five same-revision
workflows for repository quality, the Python test matrix, coverage publication,
distribution integrations and the VS Code host. Update the versioned
[workflow inventory](.github/ci-workflows.json) whenever jobs or ownership change.
Every executable job has exactly one declared category and owner.

Each supported Python interpreter keeps eight Linux shards. Windows and macOS
producers provide native data for the same exact interpreter version. Native
jobs and the Windows editor hosts use the isolated CI Python action. It verifies
the pinned uv archive SHA-256 before extracting and running the executable in a
fresh runner directory. Its managed x64 CPython catalog supplies patch versions
that GitHub's runner cache and setup-python manifest omit on those platforms.
The action verifies the exact runtime, bootstraps bundled pip and keys its cache
by interpreter identity and lock files. The union requires all eight shards and
both native platforms with matching source, Git revision, run ID and attempt.
Parent calls, subtests, JUnit and the original
branch databases are validated before reporting. The package-wide 98% gate and
exact native-dispatch gate remain separate from the Python 3.12 whole-file 100%
gate for the native backend and its maintained tests.

Ordinary native profiles always exclude the two separately required primary
acceptance owners. The Windows Python 3.12 `native-primary` job runs those two
unchanged owners, requires all twelve successful controls and enforces their
complete test-owner coverage. Its artifact is separate from ordinary native
artifacts and never enters the ordinary coverage union. Both roles are required
by the test category and the aggregate CI gate.

Native receipts use schema version 2 and explicitly bind `ordinary` or `primary`.
Old mixed or unannotated receipts are refused. Before any ordinary branch data
is read, the consumer checks database file and context metadata for reserved
owners. Linux ordinary shards exclude those modules before collection imports;
they remain mandatory in the separate primary acceptance job.

Native tooling qualification consumes two distinct Windows Python 3.12 artifacts:
`RIGOR_NATIVE_PRIMARY_EVIDENCE_DIR` names the primary artifact and
`RIGOR_NATIVE_WINDOWS_EVIDENCE_DIR` names the ordinary artifact. They must never
point at the same producer. A retained older ordinary artifact also needs its
exact source checkout through `RIGOR_NATIVE_WINDOWS_SOURCE_ROOT`, and must meet
the current versioned receipt contract. Local ordinary receipts retain their
local venue; hosted admission requires the GitHub venue and current run identity.

After workflow edits, run Actionlint and focused policy tests, then the normal
action-pin guard; it also checks the complete inventory and graph:

```bash
actionlint
python -m tools.check_ci_workflows
python -m pytest tests/test_ci_workflows.py tests/test_ci_native_workflows.py tests/test_check_ci_workflows.py --cov=tools.ci_workflows --cov=tools.ci_native_workflows --cov=tools.check_ci_workflows --cov=test_ci_workflows --cov=test_ci_native_workflows --cov=test_check_ci_workflows --cov-branch --cov-report=term-missing --cov-fail-under=100
python -m tools.check_action_pins
```

Quality CI runs the same tests and a digest-verified Actionlint 1.7.12 binary.
The CI gate requires success from every category, including the complete Python
matrix. Coverage upload keeps its OIDC permission and runs only after tests;
failed, cancelled or skipped categories fail the aggregate.
Before publishing a workflow migration, verify the emitted category and
aggregate check names against actual required contexts and bind the stable
aggregate accordingly. Local validation does not activate hosted protection.

Native observation admission also requires the emitted scheduling strategy and
advisory duration snapshot to match the source-bound receipt identity. The
producer refuses publication after mismatched finalisation output, and the
consumer refuses changed observations even if their artifact digest was updated.

Editor native artifacts have a separate Windows producer. It runs the locked
MSVC build once and binds the payload to the complete editor source inventory
and current GitHub revision, repository, run and attempt. Its downstream editor
jobs admit that exact artifact before executing tests. Four actual profiles cover
both supported OS families at the minimum and pinned current host versions.
The required consumer validates all original producers and the complete
source/compiled-map identity before the whole-owner 100% union and both VSIX
packages. Keep producer, admission, matrix, union and packaging order aligned
with `tools.ci_editor_workflows` and its
dedicated `tests/test_ci_editor_workflows.py` contract cases. The local
`native-artifact.mjs pack` command retains genuine existing bytes with a local
receipt; it cannot substitute for the required hosted build.
