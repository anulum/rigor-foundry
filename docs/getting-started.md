# First repository

This tutorial creates an adopter-owned policy and private work ledger without
letting RigorFoundry guess their locations or overwrite existing project data.

## Install and identify the tool

Use an exact published version or a reviewed source checkout, then record the
version that will create the policy:

```bash
python -m pip install "rigor-foundry==0.1.1"
rigor --version
```

The expected output is `rigor 0.1.1`. A policy, report, or campaign remains
bound to its own schema and scanner identities; the package version is not a
substitute for those content identities.

## Declare private paths first

From the root of the Git worktree, create the parent of the internal ledger and
make Git ignore the exact internal namespace. The policy itself must remain
trackable:

```bash
mkdir -p docs/internal
printf '%s\n' 'docs/internal/' >> .gitignore
git check-ignore --quiet --no-index docs/internal/TODO.md
git check-ignore --quiet --no-index docs/internal/reviews.json
```

Review `.gitignore` before committing it. Do not use a broad rule that hides
the policy or production source.

## Bootstrap explicit paths

Pass every adopter-owned path and every current source/test root. Repeat
`--source-root` or `--test-root` for additional roots:

```bash
rigor bootstrap \
  --root . \
  --policy rigor-foundry-policy.json \
  --todo docs/internal/TODO.md \
  --review-ledger docs/internal/reviews.json \
  --source-root src \
  --test-root tests
```

Bootstrap succeeds only when:

- `--root` is the exact real Git worktree root, not a symlink or subdirectory;
- source/test roots and the parents of new files already exist without symlink
  components;
- the policy path is untracked, absent, and not ignored;
- TODO and review-ledger paths are untracked and already ignored; and
- policy, TODO, and review-ledger paths are distinct and repository relative.

The command creates the policy as a regular `0644` file and the canonical TODO
as a private `0600` file. It never creates or adopts the review ledger, guesses
a TODO, creates parent directories, follows symlinks, or overwrites an existing
path. If a concurrent mutation or second-file failure occurs after one file is
created, bootstrap fails and preserves the created evidence. Inspect it before
retrying; the tool never performs a pathname-based rollback that could delete a
concurrent writer's replacement.

## Review the fail-closed policy

The generated policy starts in `observe` mode with a 700-line production
threshold, a 1000-line test threshold, and every audit domain marked
`required`. This is deliberate: RigorFoundry cannot infer which security,
architecture, compliance, performance, or operational domains apply to a new
repository.

Before treating scan output as a project gate:

1. Review every `audit_domains` entry and record repository-specific evidence
   for any `not-applicable` decision.
2. Add production-package roots, module-size registries, and native adapters
   that are actually owned and executable in the adopter environment.
3. Review thresholds and keep enforcement in `observe` until the baseline and
   review ledger are evidence-bound.
4. Commit the policy and `.gitignore`; keep the canonical TODO and review
   ledger ignored.

## Run the first read-only scan

```bash
rigor scan \
  --root . \
  --policy rigor-foundry-policy.json \
  --json-out docs/internal/first-report.json
```

The report contains candidates, not verdicts. Undeclared controls, missing
native evidence, and unresolved domain decisions must remain visible rather
than being converted into a clean result. Use `review-template`,
`validate-review`, and an independent campaign before promoting a verified
finding into the canonical TODO.
