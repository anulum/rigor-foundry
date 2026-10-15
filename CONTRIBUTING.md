# Contributing

## Before editing

1. Read `ARCHITECTURE.md`, `VALIDATION.md`, and the public roadmap.
2. Use a fork or isolated worktree and submit a focused pull request. Maintainers
   additionally claim exact paths before editing a shared worktree.
3. Keep public product code, internal audit evidence, and adopter-specific
   findings in their defined boundaries.
4. Keep each branch and pull request limited to one coherent responsibility.

## Environment

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements/ci.txt
.venv/bin/python -m pip install --no-build-isolation --no-deps -e .
make install-hooks
```

## Dependency maintenance

Maintainers review dependency alerts and available versions weekly. Python
updates use an owner-controlled batch because the automated updater removes
lock-generation provenance. Regenerate affected hash locks with the pinned
`pip-tools` on Python 3.11, retain their generation commands and mandatory
metadata, and align shared versions across build, CI, runtime, security and test
inputs. The security lock follows the same Python 3.11 generation contract;
its exact command is in [Security-tool lock maintenance](docs/security.md#security-tool-lock-maintenance).
Record upstream compatibility bounds when a newer release cannot be installed.
Verify the complete dependency diff and scoped checks before review;
remote CI validates the published commit. Dependency detection and alerts remain
enabled. CodeQL action steps are updated together to keep their versions equal.

## Quality contract

- Public Python symbols use complete typing and NumPy-convention docstrings.
- Strict MyPy and Ruff must report zero errors on touched scope.
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
