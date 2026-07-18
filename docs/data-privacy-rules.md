# Data-and-privacy rules

Rule-pack `rigor-foundry/1.11.0` adds a bounded data-and-privacy category (prefix
`DP`) of high-precision rules over tracked Python. Like every RigorFoundry rule,
each `DP` finding is an anchored **needs-evidence candidate**, never a verdict:
it marks a real secret-exposure surface for review, not a proven leak. The rules
are deliberately narrow to keep false positives low; breadth is not an acceptance
metric.

## Rules

| Rule | Signal | Confidence |
| --- | --- | :---: |
| `DP001-hardcoded-credential` | a credential-named variable assigned a string-literal secret | medium |
| `DP002-embedded-private-key` | a string literal containing a PEM `-----BEGIN … PRIVATE KEY-----` block | high |

`DP001` flags an assignment whose target names a credential — `password`,
`secret`, `api_key`, `access_key`, `secret_key`, `private_key`, `auth_token`,
`access_token`, `credential`, and their variants — and whose value is a string
literal. It is precise by construction: the name must contain the credential
word as a bounded identifier component (so `secretary` is not `secret`), a
concept-naming descriptor suffix is excluded (`password_hash`, `api_key_name`,
`token_type` are metadata, not the secret), and obvious non-secrets are ignored —
an empty string, a known placeholder (`changeme`, `example`, `test`, …), and an
environment or template reference (`${VAR}`, `{{ … }}`). A non-literal value such
as `os.environ["API_KEY"]` is never flagged. It is medium confidence because a
sensitive-named literal can still be a fixture or placeholder; the reviewer
confirms whether it is a live secret. `DP002` flags any string literal that
embeds a PEM private-key block — an unambiguous disclosure of key material — at
high confidence.

Each candidate carries a repository-tree anchor (path, line, content SHA-256), a
neutral rationale, and a concrete verification procedure — load the value from an
environment variable or secret manager at runtime and remove the literal, or (for
a key) remove it from source, rotate it, and load it from an out-of-tree store.

## Precision and applicability

The rules match on the Python AST, not on text, so a credential word inside a
comment or a non-Python file is not flagged, and metadata, placeholders, and
runtime lookups are ignored by construction. The category applies to every
tracked Python file, because an embedded secret is not test-only, and contributes
a portable control toward the `data-and-privacy` audit domain. It complements
regex secret scanning: it catches sensitive-named literals and embedded keys that
format-specific scanners miss, and defers known-format token detection to them.

## Calibration

False-positive calibration against real repositories is deliberately separate
work: these rules ship with safe-and-vulnerable fixtures and precise AST matching,
but adjudicated false-positive and reviewer-effort evidence across adopter
repositories is the maturity-lifecycle step that promotes a rule from candidate
breadth to calibrated enforcement.
