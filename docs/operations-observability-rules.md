# Operations and observability rules

Rule-pack `rigor-foundry/1.14.0` adds the bounded `operations` category (prefix
`OP`). Findings are anchored **needs-evidence candidates**, not proof of an
outage, secret disclosure, or inadequate observability.

## Rules

| Rule | Signal | Confidence |
| --- | --- | :---: |
| `OP001-print-in-library-code` | tracked Python library code calls builtin `print` outside a conventional command surface | medium |
| `OP002-credential-in-log-call` | an import-bound standard-library logging call directly receives a credential-named expression | high |

Both rules require tracked UTF-8 Python below an exact policy source root and
exclude test paths. OP001 also excludes top-level `tools`, `scripts`, and `bin`
roots plus `cli.py`, `__main__.py`, and `*_cli.py` modules. It recognises local
or module shadowing of `print` and separately detects explicit
`builtins.print`. Reviewers should replace incidental process output with a
return value or structured logger, or prove the module is an intentional
command boundary.

OP002 resolves explicit `logging` imports, `getLogger` aliases, assigned logger
instances, and chained `logging.getLogger(...).method(...)` calls for the
standard debug/info/warning/error/critical/exception/log methods. Only variable
or attribute names that identify credential material trigger; message labels,
arbitrary payloads, custom logging frameworks, and names ending in metadata
descriptors such as `hash`, `digest`, `id`, or `path` do not. Reviewers must
remove or redact the value and inspect captured output at the real logging
boundary.

Syntax-invalid Python yields no OP candidate because the existing authenticity
rule owns parse failure. Evidence contains exact tracked-blob and line/file
digests without copying source or credential values. Absence of OP002 is not
proof that logs contain no secrets; dynamic values and unsupported logging
frameworks require separate evidence.

The family contributes a portable control to `operations-and-observability`.
Both rules enter maturity probation and cannot drive enforcement until
adjudicated cross-repository precision and reviewer-effort evidence exists.
