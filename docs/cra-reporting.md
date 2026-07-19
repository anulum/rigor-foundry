# Offline CRA Article 14 preparation

RIGOR-FOUNDRY can prepare evidence-bound drafts and operational timelines for
Article 14 of Regulation (EU) 2024/2847. The feature is deliberately offline:
it does not contact the Single Reporting Platform, ENISA, a CSIRT, users,
maintainers, or any other authority. It does not decide whether the Regulation
applies, submit a report, establish legal sufficiency, assess conformity or CE
readiness, or adjudicate severity.

The manufacturer remains responsible for applicability decisions, the content
of every unresolved operator field, and every external submission or user
communication. The official sources are the [current Regulation
text](https://eur-lex.europa.eu/eli/reg/2024/2847/oj) and the European
Commission's [CRA reporting overview](https://digital-strategy.ec.europa.eu/en/policies/cra-reporting).
Article 14 applies from 11 September 2026; most other provisions apply from 11
December 2027.

## Evidence model

All state is Git-ignored below `.rigor/cra/`. Records use schema `1.0`, exact
whole-second UTC timestamps ending in `Z`, deterministic JSON, and lowercase
SHA-256 addresses. Authoritative records are append-only. Reads replay the
complete event revision chain, record filenames, embedded digests, payload
paths, and exact payload bytes. A fork, missing parent, cross-wired record,
unknown revision, mutation, duplicate stage state, symbolic link, hard link,
or unsafe path fails closed.

The two tracks are separate:

- `vulnerability` requires non-empty operator-supplied active-exploitation
  evidence;
- `incident` requires a severe-incident prong, its evidence reference, and an
  explicit suspected-cause state, which may be `unknown`.

Early warning is due at awareness plus 24 hours and notification at awareness
plus 72 hours. A vulnerability final-report clock starts only when a corrective
measure becomes available and uses 14 days. An incident final-report clock
starts only from a notification receipt or a valid notification skip bound to
an earlier receipt; its conservative operational deadline is the same instant
one calendar month later with end-of-month clamping. At the exact deadline a
stage is not overdue; one second later it is.

A generated draft without a bound operator receipt is
`submitted-unverified`. It creates an operational alert after 24 hours. That
alert is a RIGOR-FOUNDRY workflow signal, not a statutory CRA deadline.

## Initial product registration

Run the command inside an existing Git repository whose `.gitignore` covers
`.rigor/`. It refuses any pre-existing CRA state.

```bash
rigor cra-bootstrap \
  --root . \
  --product-key widget \
  --product-name "Widget" \
  --manufacturer-name "Example Manufacturer" \
  --main-establishment-ms DE \
  --establishment-basis decisions \
  --csirt-endpoint-id operator-declared-csirt \
  --user-notice-channel security-page \
  --support-period-months 60 \
  --registered-at 2026-09-11T08:00:00Z
```

`--main-establishment-ms` accepts an uppercase two-letter Member State or
`none-eu`. The establishment basis is an operator declaration: `decisions`,
`employees`, `auth-rep`, `importer`, `distributor`, or `users`.

For an operator-declared expected use below 60 months, provide both
`--expected-use-months` and `--expected-use-evidence-ref`. P0 stores those
declarations but never turns a support period below 60 months into a violation.

## Register or revise an event

Create a vulnerability event:

```bash
rigor vuln-register VULN-2026-001 \
  --root . \
  --product-key widget \
  --track vulnerability \
  --aware-at 2026-09-11T09:00:00Z \
  --aware-evidence evidence/awareness.json \
  --exploitation-evidence evidence/active-exploitation.json \
  --external-id CVE-2026-0001 \
  --component widget-core@1 \
  --member-state DE \
  --recorded-at 2026-09-11T09:05:00Z
```

For an incident, use `--track incident`, omit exploitation evidence, and add
`--severe-prong data-or-functions|malicious-code`, `--severe-evidence`, and
`--suspected-cause unlawful-or-malicious|not-suspected|unknown`.

Running `vuln-register` again for the same event appends a successor to the
current verified tip. The product, track, awareness trigger, and trigger
evidence cannot change. Status transitions are monotonic. Use explicit
`--recorded-at` values for reproducible automation.

## Inspect clocks and prepare drafts

```bash
rigor vuln-timeline VULN-2026-001 --root . --now 2026-09-11T10:00:00Z

rigor cra-draft VULN-2026-001 \
  --root . \
  --stage early-warning \
  --generated-at 2026-09-11T10:00:00Z
```

Draft JSON separates `statutory_minimum` from `operator_context`. Unknown facts
remain JSON `null` and the Markdown mirror calls them unresolved operator
inputs. Payloads do not claim to reproduce a future reporting-platform schema.
Every payload carries the drafting-aid, non-legal-advice, and
manufacturer-submission boundary.

The supported stages are `early-warning`, `notification`, `final-report`, and
an `intermediate` stage only when the event revision carries all three explicit
request fields: request time, due time, and evidence reference.

## Bind operator receipt evidence

RIGOR-FOUNDRY never submits a draft. After the manufacturer acts externally,
bind its retained evidence file to the exact current stage draft:

```bash
rigor cra-receipt VULN-2026-001 \
  --root . \
  --stage early-warning \
  --draft-digest DRAFT_SHA256 \
  --submitted-at 2026-09-11T10:15:00Z \
  --platform-ref operator-supplied-reference \
  --csirt-endpoint-id operator-declared-csirt \
  --evidence evidence/receipt.txt \
  --bound-at 2026-09-11T10:20:00Z
```

The evidence file must be a regular single-link file no larger than 64 MiB.
Only its SHA-256 is stored. A receipt is an operator declaration bound to the
draft and payload; it is not proof of authority acceptance or successful
submission.

## Record already-provided information

Notification and final-report may be explicitly skipped only when an earlier
available receipt already provided the information:

```bash
rigor cra-skip VULN-2026-001 \
  --root . \
  --stage notification \
  --provided-in-stage early-warning \
  --provided-in-receipt-digest RECEIPT_SHA256 \
  --reason "notification information already provided" \
  --evidence-ref evidence/operator-decision.json \
  --skipped-at 2026-09-11T10:25:00Z
```

The referenced stage must precede the skipped stage. A stage cannot have both
a receipt and a skip. For an incident notification skip, the referenced
earlier receipt time becomes the conservative final-report clock anchor.

## Prepare an Article 14(8) user notice

```bash
rigor user-notice VULN-2026-001 \
  --root . \
  --audience impacted \
  --machine-readable \
  --generated-at 2026-09-11T11:00:00Z
```

This creates prepare-only JSON and Markdown. It does not send the notice or
claim that the notice is timely.

## Aggregate status and exit codes

```bash
rigor cra-status --root . --now 2026-09-11T12:00:00Z --json
```

Use `--event-key` to inspect one event. All timeline and status commands accept
`--now` for deterministic operation.

- exit `0`: verified state with no overdue stage and no unverified draft older
  than 24 hours;
- exit `1`: at least one overdue stage, late receipt/skip, or stale unverified
  draft;
- exit `2`: invalid arguments, malformed or unsafe state, digest mismatch,
  ambiguous chain, or I/O failure.

Fixed-vulnerability advisories, SBOM import, OSV integration, CRA rule packs,
policy extensions, editor UI, fleet aggregation, network submission, and user
delivery are outside this P0 boundary.
