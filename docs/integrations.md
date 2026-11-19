# Consumer integrations

RigorFoundry publishes a composite GitHub Action and a pre-commit hook for
adopter-owned audit gates. Both integrations are evidence-only surfaces: they
can scan and evaluate an existing policy, but they cannot promote findings,
apply remediation, edit source, create policy state, or infer private paths.

## GitHub Action

Pin the Action and every other workflow action to a complete commit SHA. The
examples use the exact commit of the [published 1.0.0 release](https://github.com/anulum/rigor-foundry/releases/tag/v1.0.0)
for both the Action and the hook:

```yaml
name: RigorFoundry

on:
  pull_request:

permissions:
  contents: read

concurrency:
  group: rigor-foundry-${{ github.ref }}
  cancel-in-progress: true

jobs:
  audit:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0
        with:
          persist-credentials: false
      - name: Prepare explicit ignored output parent
        run: mkdir -p .rigor/reports
      - name: Run read-only evidence gate
        uses: anulum/RIGOR-FOUNDRY@8de2ecee35c7baa0e4e1dc5500e555a25ab82496
        with:
          repository-root: .
          policy-path: rigor-foundry-policy.json
          report-path: .rigor/reports/report.json
          gate-report-path: .rigor/reports/gate.json
          mode: observe
          scope: full
          allow-native-audits: "false"
```

The output parents must already exist and both output files must be absent; the
Action never overwrites a file or creates repository directories. An output
inside the adopter worktree must be Git-ignored and untracked. The Action
installs the exact checked-out source revision with Python 3.12.11, the
hash-locked build requirements, and the hash-locked runtime requirements. The
PEP 517 backend and all four of its build dependencies are exact requirements
as well. Nested `setup-python` is itself pinned to a full commit. Inputs enter
Bash only through quoted environment variables.

The current-source Action first installs the hash-locked source-build bootstrap
in its new interpreter, then installs the build/runtime locks without build
isolation. The immutable example above identifies its published source revision;
it does not acquire later source changes.

`repository-root`, repository-relative tracked `policy-path`, `report-path`, and `gate-report-path` are
mandatory. `mode` accepts only `observe`, `ratchet`, or `zero`; `scope` accepts
only `staged` or `full`. Ratchet and zero require an explicit `maturity-path`
whose policy identity is already bound by the repository policy. An optional
`review-path` replaces the policy-declared review ledger. A requested mode may
strengthen the policy but cannot weaken it.

`allow-native-audits` defaults to `false`. Setting it to `true` is explicit
consent only for policy-declared adapters running through the existing
read-only sandbox; it grants no remediation authority. The Action contains no
`promote` or `--apply` path.

## Pre-commit hook

Pin `rev` to the same complete commit SHA. The published hook defaults to the
staged observe gate with `rigor-foundry-policy.json`. To retain an explicit gate
artifact, configure the complete argument vector because adopter `args`
replace, rather than extend, the manifest defaults:

```yaml
minimum_pre_commit_version: 4.6.0
repos:
  - repo: https://github.com/anulum/RIGOR-FOUNDRY
    rev: 8de2ecee35c7baa0e4e1dc5500e555a25ab82496
    hooks:
      - id: rigor-foundry
        entry: .rigor/rigor-venv/bin/rigor
        args:
          - gate
          - --root
          - .
          - --policy
          - rigor-foundry-policy.json
          - --mode
          - observe
          - --scope
          - staged
          - --output
          - .rigor/reports/pre-commit-gate.json
```

Create and ignore `.rigor/reports` before running the hook. The hook uses
`language: system` deliberately: pre-commit's Python environment installer does
not expose pip's `--require-hashes` contract. Install the pinned RigorFoundry
checkout into `.rigor/rigor-venv` with the `requirements/build.txt` and
`requirements/runtime.txt` hash locks from that same immutable revision, followed
by `pip install
--no-build-isolation --no-deps CHECKOUT`; then retain the explicit `entry`
shown above. The manifest runs once serially without filenames and does not
consent to native adapters. For ratchet or zero, replace the complete `args`
list, select the stronger mode, and add `--maturity PATH`. Add `--review PATH`
only when the review ledger is explicitly owned. Add `--allow-native-audits`
only after reviewing the declared adapter commands and sandbox prerequisites.

For a current-source checkout, install `requirements/bootstrap.txt` into that
interpreter before the build/runtime locks and pass `--no-build-isolation` for
subsequent lock installation. Keep the current-source setup separate from the
release example. Use the locks from the exact revision you install.

### Native Windows hook

The published `1.0.0` package requires a POSIX runtime. On native Windows, use
a Windows-capable build and the hook manifest from its verified source revision.
Follow the [installation and recovery instructions](getting-started.md#install-and-identify-the-tool).
Set the pre-commit `entry` to `.rigor/rigor-venv/Scripts/rigor.exe` when that is the
installation path. Use forward slashes in the entry because pre-commit parses
backslashes as escapes.

## Upgrade and rollback

Treat the Action SHA, hook Git revision and hook installation as one set. Retain
the existing pins, locks and hook installation before switching. Keep the same
tracked policy and use fresh ignored output paths for the new reports. Run the
new set in observe mode when the policy allows it. Compare exact report and
gate identities only when both runs use the same checkout and evidence inputs.
For separate environments, verify each gate against its own report and check
the expected policy digest and Git state for that environment.

Restore the prior pins and hook installation together to roll back. Use another
fresh output path to confirm the restored gate. On native Windows, restore the
last working Windows-capable build and its matching hook revision.

## Verification boundary

Distribution CI builds and checks the wheel and source distribution, creates a
separate real Git adopter under `/tmp`, bootstraps and commits its policy, runs
the local composite Action against that repository, then makes pre-commit clone
the source repository at the exact `${GITHUB_SHA}` and execute the system hook
through the hash-locked installed wheel. The workflow requires non-empty Action
scan, Action gate, and pre-commit gate artifacts. Local author evidence repeats
the Action shell and hook install
against an external fixture; hosted CI remains the authoritative runner proof
after an authorised push.

These integrations report policy evidence. They do not establish that every
audit domain is implemented, that candidates are defects, that reviewed
findings are resolved, or that the repository is production-ready.
