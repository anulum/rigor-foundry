# SARIF export

RigorFoundry emits deterministic
[SARIF 2.1.0 Errata 01](https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os-complete.html)
without converting static audit candidates into defect verdicts.

```bash
rigor sarif --report report.json --output results.sarif
rigor sarif --report report.json --review reviews.json --output results.sarif
```

The command verifies report integrity and validates every supplied review.
Duplicate, incomplete, foreign, or stale review records fail closed. Omitting
`--output` writes the same deterministic JSON to stdout.

## State mapping

| RigorFoundry state | SARIF `kind` | SARIF `level` |
| --- | --- | --- |
| unreviewed candidate | `review` | `note` |
| `needs-evidence` | `review` | `note` |
| reviewed `valid`, P0/P1 | `fail` | `error` |
| reviewed `valid`, P2 | `fail` | `warning` |
| reviewed `valid`, P3/P4 | `fail` | `note` |
| reviewed `invalid` | `notApplicable` | `none` |
| reviewed `accepted-boundary` | `informational` | `note` |

Every report candidate remains a result. The property bag records separate
`rigorFoundry/candidateState` and `rigorFoundry/verdictState` values, so a SARIF
consumer can distinguish scanner evidence from a human evidence decision.
Severity provenance is `review-record` only when a validated review provides a
severity.

## Rule help and categories

Every rule descriptor carries the rule summary as `shortDescription`, the
detector's fixed rationale as `fullDescription`, and `help` with plain-text and
Markdown forms that add the verification guidance. Each `helpUri` points at the
rule's own section of the generated [rule catalogue](rule-catalogue.md). The
guidance is the same fixed text that the detector attaches to every candidate of
that rule, so the catalogue and the results cannot disagree. Two rules have two
distinct situations; their full description joins both rationales and their help
lists both cases.

Each run declares one taxonomy, `RigorFoundry rule categories`, whose taxa are the
rule-pack categories in registry order. Every rule relates to its category with
kind `subset`. RigorFoundry emits no rule-level `security-severity`: severity is
recorded only by a validated review, never by a rule.

## Identity and anchors

Rule IDs and indices come from the complete versioned RigorFoundry rule pack.
The content-addressed candidate ID is exported as the exact `rigorFoundry/v1`
fingerprint. RigorFoundry does not claim a GitHub `primaryLocationLineHash`
without the scanned line bytes required to compute that separate identity.
Locations use percent-encoded repository-relative paths and inclusive spans.

The `rigorFoundry/anchor` property preserves the strict anchor schema. A
tracked-blob result includes the exact scanned Git blob OID and content
SHA-256. A repository-tree result includes the exact HEAD tree OID and complete
tracked-content SHA-256. Run properties also bind the report, policy, ignored
inventory, tracked content, rule-pack, HEAD, tree, and Git object format.

The schema URI is exported as `SARIF_SCHEMA_URI`; its current value identifies
the OASIS SARIF 2.1.0 Errata 01 JSON schema. `report_sarif` and the schema/version
constants are provisional package-level APIs. Their lifecycle is independent
of the stable SARIF wire contract; see [Public API stability](api-stability.md).
