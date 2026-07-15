# Contributing

## Before editing

1. Read `ARCHITECTURE.md`, `VALIDATION.md`, and the public roadmap.
2. Use a fork or isolated worktree and submit a focused pull request. GOTM
   operators additionally claim exact paths before editing a shared worktree.
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

Run focused tests locally:

```bash
.venv/bin/pytest -q tests/test_models.py
make preflight-fast
```

GOTM authoring sessions reserve the exhaustive matrix for CI under fleet
resource policy. External contributors may run it locally with
`ALLOW_LOCAL_FULL_TESTS=1 make test`; the same matrix remains a required remote
gate.

## Commits and review

Commits are atomic and use Conventional Commits. Agent-assisted GOTM commits
contain exactly one vendor-neutral `Seat:` trailer and exactly one authorship
line; human and external contributor commits do not add these internal fleet
trailers:

```text
Seat: <seat-id>

Authored by Anulum Fortis & Arcane Sapience (protoscience@anulum.li)
```

In the GOTM shared worktree, the author does not push their own commit. A peer
audits the exact SHA in isolation and records the gate outcome before any push.
External contributions follow the ordinary fork and pull-request review flow.

## Internal material

For GOTM operators, coordination logs and handovers live only in the monorepo
`.coordination/{sessions,handovers}/RIGOR-FOUNDRY/`. Repository-local
`docs/internal/` is ignored and may hold non-public product audit evidence;
external contributors should not create it.
Never commit credentials, private repositories, internal plans, or audit
reports containing proprietary source excerpts.
