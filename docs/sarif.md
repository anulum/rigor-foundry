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

## Hosted code-scanning upload

The `Code scanning` workflow (`.github/workflows/code-scanning.yml`) uploads this
repository's own audit to GitHub code scanning on every push to `main`, and
never on a pull request. Its single job has only `contents: read` and
`security-events: write`. It does not depend on any other job, so no other
job's result can hide its own. It runs these steps in order:

1. Install the hash-locked runtime.
2. Run `rigor scan` on the exact checkout.
3. Run `python -m tools.check_sarif_upload_checkout`. It refuses the upload
   unless the checkout's `HEAD` and `HEAD^{tree}` are the report's `head` and
   `head_tree`, because GitHub fills result fingerprints from the files of the
   checkout it uploads from.
4. Write the GitHub code-scanning profile, which refuses GitHub's upload limits
   before writing anything.
5. Upload the profile with the same pinned `upload-sarif` action as the
   Scorecard workflow, in category `rigor-foundry`.

The repository tracks no review ledger, so no result is reviewed `valid` and the
uploaded profile holds no results. A run therefore opens no alert and proves the
wiring: GitHub lists a RigorFoundry analysis for the commit in category
`rigor-foundry`. Its run properties declare the omitted count of every candidate
and the digest of the canonical export.

## CWE taxonomy

Each run also declares a second taxonomy, `CWE`. It is pinned to CWE List
version 5.0 (released 2026-10-28) and holds only the CWE ids that reviewed
mappings name. A mapped rule relates to its CWE entry with kind `relevant`, never
`equal`. A candidate of that rule marks a surface related to the weakness, and
only an evidence review can decide whether the weakness is present. The mapping
lives in the packaged `cwe_mapping.json`. Each entry pairs one rule with one CWE
id and a one-sentence justification that cites that entry, together with the
record of the evidence review that admitted it. Loading refuses an unreviewed,
duplicated, unregistered or uncited entry. A rule without a reviewed mapping
claims no CWE. The [rule catalogue](rule-catalogue.md) shows each mapping and
its justification. The export names CWE entries only by id and link; it carries
no CWE names or descriptions. CWE is a trademark of The MITRE Corporation.

## GitHub code-scanning profile

```bash
rigor sarif --report report.json --review reviews.json --profile github-code-scanning \
  --output github.sarif
```

GitHub code scanning presents every uploaded result as an alert, so this profile
keeps only results whose validated review decision is `valid`. The canonical
export without `--profile` is unchanged and keeps every candidate. The profile's
run properties declare `rigorFoundry/consumerProfile`, the omitted result count
for each state in `rigorFoundry/omittedResults` (`unreviewed`, `needs-evidence`,
`invalid`, `accepted-boundary`), and `rigorFoundry/canonicalDocumentDigest`, the
SHA-256 of the canonical document for the same report and reviews.

Before anything is written, the profile refuses GitHub's documented upload limits:
20 runs per file, 25,000 rules per run, 20 tags per rule, 1,000 locations per
result and 10 MB of gzip-compressed SARIF per file. It also refuses more than
5,000 results, because GitHub shows only the top 5,000 and would otherwise drop
results silently. The error names the exceeded count and the command exits 2.

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

## Third-party SARIF import

`rigor import-sarif` imports one SARIF 2.1.0 file from a declared producer into
an import report, schema `rigor.import-report.v1`. It is separate from the audit
report. Imported findings stay `unreviewed` candidates: nothing in the import
adjudicates them, and the audit report, the rule registry, the rule-pack digest
and the SARIF export stay byte-identical.

- **Declared producers.** CodeQL, Semgrep and Trivy are declared in code, each by
  the driver name, version field, supported versions, exact `$schema` URI and root
  `uriBaseId` that its real output uses. A version must be exactly
  `MAJOR.MINOR.PATCH` with no leading zero. Its major must be declared, and a
  major-zero producer declares its supported minors instead, since any 0.x minor
  may change the format: Trivy 0.76 only. A file from another producer, with
  another driver, schema or version, or claiming different drivers in different
  runs is refused as a whole. RigorFoundry's own SARIF, in any run, is refused as
  a self-import.
- **One commit.** Every `versionControlProvenance[].revisionId` of every run must
  equal the checkout's HEAD. When any run states none, `--head` must name that
  HEAD.
- **Whole-file limits.** The import refuses a file over 32 MiB, one that is not
  strict JSON (duplicate keys and non-finite numbers included), nesting deeper
  than 64, more than 8 runs, more than 100,000 results in a run, or more than
  20,000 rules across a run's driver and tool extensions.
- **Rules.** Imported rules live in their own `ext:<producer>:<ruleId>`
  namespace, per tool component, so rules kept in a query-pack extension resolve
  through `rule.toolComponent.index`. A candidate identifier binds the producer,
  the rule, the rule's component name and version, the anchor, the message digest
  and the partial fingerprints. A producer's own `fingerprints` are kept as data.
- **Locations.** A relative URI, a URI under a declared root `uriBaseId`, or an
  absolute `file:` URI under the checkout (or `--checkout-root`) must resolve,
  after decoding exactly once, to one clean tracked blob, compared exactly and
  never through a symbolic link. The `startLine` to `endLine` span becomes the
  anchor. A result without a physical artifact location is an unanchored
  observation, and a non-finding `kind` is an observation wherever it points.
- **Preservation.** Level, kind, baseline state, suppressions, fingerprints and
  properties are kept verbatim within fixed bounds, and by digest beyond them.
  Nothing is mapped onto RigorFoundry severity, confidence or category. A field
  of the wrong SARIF type, `null` included, skips its result with a reason.
  `--require-all-anchored` exits 1 when any result was skipped or any finding is
  an unanchored observation.
- **Provenance.** Every import is `declared`: the producer identity is the
  file's own claim, recorded with the driver name and version it states. Imports
  bound to an executed adapter-profile run are not available yet.
