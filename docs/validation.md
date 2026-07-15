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

Release eligibility additionally requires exact-version metadata, wheel and
source-distribution checks, hashes, SBOM evidence, signatures, provenance, an
independent audit, and explicit owner authorisation. See the repository
[validation matrix](https://github.com/anulum/RIGOR-FOUNDRY/blob/main/VALIDATION.md).
