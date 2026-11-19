# First repository

This tutorial creates an adopter-owned policy and private work ledger without
letting RigorFoundry guess their locations or overwrite existing project data.

## Install and identify the tool

On a POSIX runtime, install the published `1.0.0` wheel:

```bash
python -m pip install "rigor-foundry==1.0.0"
rigor --version
```

The expected output is `rigor 1.0.0`. The published wheel imports the POSIX
`fcntl` module during startup and fails on native Windows. On native Windows,
install a wheel built from a verified source revision with Windows support.
Keep the wheel's SHA-256 and its runtime dependency lock together so you can
reinstall the working build. A source-built wheel can also report `rigor 1.0.0`.

Before replacing an installation, retain the exact working wheel and its
dependency lock, along with the tracked policy and its reports. Restore the
wheel and its matching lock together when rolling back. On native Windows,
restore the Windows-capable wheel.

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
as a private `0600` file. It never creates the review ledger and rejects one
present at either validation sample. Ledger absence is not reserved atomically:
a concurrent owner can populate the declared path after the final sample. The
command does not guess a TODO, create parents, follow symlinks, or overwrite an
existing path. If a concurrent mutation or second-file failure occurs after one
file is created, bootstrap fails and preserves the created evidence. Inspect it
before retrying; the tool never performs a pathname-based rollback that could
delete a concurrent writer's replacement.

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

## Compare reports across an upgrade

Keep the original report and write the new scan to a separate path. Use
[`rigor report-diff`](report-diff.md) to compare the two reports. If the rule
pack changed, pass `--declare-rule-pack-change` with a justification. Review
validation and SARIF export require the scanner and rule pack that produced
the report. Use the recorded working installation to reproduce those
outputs from a historical report.

## Add a repository gate

After committing the reviewed policy, adopt the pinned GitHub Action or
pre-commit hook from [Consumer integrations](integrations.md). Create and
ignore the exact report parent first. Begin in observe mode; ratchet and zero
require an explicit maturity report already bound by policy. Neither
integration can apply remediation or promote findings.
