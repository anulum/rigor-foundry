# Consumer integrations

RigorFoundry publishes a composite GitHub Action and a pre-commit hook for
adopter-owned audit gates. Both integrations are evidence-only surfaces: they
can scan and evaluate an existing policy, but they cannot promote findings,
apply remediation, edit source, create policy state, or infer private paths.

## GitHub Action

Pin the Action and every other workflow action to a complete commit SHA. The
following revision is the provenance-hardened integration successor containing
`action.yml`, `.pre-commit-hooks.yaml`, and the executable-provenance guards:

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
        uses: anulum/RIGOR-FOUNDRY@cd7a06d6c2e6c1258006ade83aff5e94d5fb1cb2
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
    rev: cd7a06d6c2e6c1258006ade83aff5e94d5fb1cb2
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
checkout into `.rigor/rigor-venv` with its `requirements/build.txt` and
`requirements/runtime.txt` hash locks, followed by `pip install
--no-build-isolation --no-deps CHECKOUT`; then retain the explicit `entry`
shown above. The manifest runs once serially without filenames and does not
consent to native adapters. For ratchet or zero, replace the complete `args`
list, select the stronger mode, and add `--maturity PATH`. Add `--review PATH`
only when the review ledger is explicitly owned. Add `--allow-native-audits`
only after reviewing the declared adapter commands and sandbox prerequisites.

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
