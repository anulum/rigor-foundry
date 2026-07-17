# Consumer integrations

RigorFoundry publishes a composite GitHub Action and a pre-commit hook for
adopter-owned audit gates. Both integrations are evidence-only surfaces: they
can scan and evaluate an existing policy, but they cannot promote findings,
apply remediation, edit source, create policy state, or infer private paths.

## GitHub Action

Pin the Action and every other workflow action to a complete commit SHA. The
following revision is the reviewed integration successor that contains both
`action.yml` and `.pre-commit-hooks.yaml`:

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
        uses: anulum/rigor-foundry@0ad072dac61f0d757aa91e45dfec2960e4b177c1
        with:
          repository-root: .
          policy-path: rigor-foundry-policy.json
          report-path: .rigor/reports/report.json
          gate-report-path: .rigor/reports/gate.json
          mode: observe
          scope: full
          allow-native-audits: "false"
```

The output parents must already exist; the Action does not create repository
directories. Keep the output namespace ignored unless the project has an
explicit evidence-publication policy. The Action installs the exact checked-out
source revision with Python 3.12.11, the hash-locked build requirements, and the
hash-locked runtime requirements. The PEP 517 backend and all four of its build
dependencies are exact requirements as well. Nested `setup-python` is itself
pinned to a full commit. Inputs enter Bash only through quoted environment
variables.

`repository-root`, `policy-path`, `report-path`, and `gate-report-path` are
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
  - repo: https://github.com/anulum/rigor-foundry
    rev: 0ad072dac61f0d757aa91e45dfec2960e4b177c1
    hooks:
      - id: rigor-foundry
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

Create and ignore `.rigor/reports` before running the hook. The manifest pins
Cryptography, CFFI, and pycparser to the exact runtime-lock versions, runs once
serially without filenames, and does not consent to native adapters. For
ratchet or zero, replace the complete `args` list, select the stronger mode,
and add `--maturity PATH`. Add `--review PATH` only when the review ledger is
explicitly owned. Add `--allow-native-audits` only after reviewing the declared
adapter commands and sandbox prerequisites.

## Verification boundary

Distribution CI builds and checks the wheel and source distribution, creates a
separate real Git adopter under `/tmp`, bootstraps and commits its policy, runs
the local composite Action against that repository, then makes pre-commit clone
the source repository at the exact `${GITHUB_SHA}` and execute the published
hook. The workflow requires non-empty Action scan, Action gate, and pre-commit
gate artifacts. Local author evidence repeats the Action shell and hook install
against an external fixture; hosted CI remains the authoritative runner proof
after an authorised push.

These integrations report policy evidence. They do not establish that every
audit domain is implemented, that candidates are defects, that reviewed
findings are resolved, or that the repository is production-ready.
