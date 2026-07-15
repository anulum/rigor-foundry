# Validation

Local development is deliberately resource-bounded. Run the static checks and
the focused test file that owns the changed production surface:

```bash
make lint
make typecheck
make bandit
make audit
make test-file TEST=tests/test_name.py
```

The exhaustive suite, aggregate branch-coverage threshold, Python 3.11–3.13
matrix, CodeQL, and OpenSSF Scorecard remain remote gates. A release-candidate
local closeout may additionally run the hash-locked dependency audit, Semgrep,
package installation smoke, hardened container smoke, and strict documentation
build; those local results do not replace the corresponding remote evidence.

The quality job also scans the clean checkout with
`rigor-foundry-policy.json`, runs every full-scope native control in observe
mode, and retains the report, Markdown rendering, and gate record for 30 days.
Observe mode preserves candidate evidence without misrepresenting static
signals as reviewed defect verdicts.

The Git provenance owner tests use real executable files and temporary Git
repositories. They cover fixed-root selection under hostile `PATH`, symlinked
roots and executables, post-capture replacement, unsupported versions, durable
report/campaign binding, filesystem-monitor suppression, reserved hook-path
rejection, CLI configuration, and campaign divergence. These focused tests do
not replace the hosted Python-version matrix.

Release eligibility additionally requires exact-version metadata, wheel and
source-distribution checks, hashes, SBOM evidence, signatures, provenance, an
independent audit, and explicit owner authorisation. See the repository
[validation matrix](https://github.com/anulum/RIGOR-FOUNDRY/blob/main/VALIDATION.md).
