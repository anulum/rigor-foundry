# Compliance evidence maps and OSCAL export

RigorFoundry can relate its per-control audit evidence to named external control
standards and export the result as [OSCAL](https://pages.nist.gov/OSCAL/)
assessment results. These surfaces are for triage and reporting only. They are
**not** a certification, an attestation, or a claim of compliance with any
standard.

## What a template is

An evidence-map template names one external standard and maps every RigorFoundry
audit domain to that standard's control identifiers, or declares an explicit gap
where no relevant control exists. A silent gap is never permitted: every domain
carries an explicit decision.

Each mapping records an honest relation strength:

- `supporting` — the domain evidence directly supports the control objective;
- `partial` — the evidence supports one aspect of the control;
- `context` — the evidence is contextual input only.

Templates reference external control **identifiers** (for example `A.8.28` or
`CC7.1`) and name each standard's edition and licence. They never reproduce
copyrighted control text.

## Built-in templates

| Template id | Standard | Edition (verified at source) |
| --- | --- | --- |
| `iso-iec-27001-2022` | ISO/IEC 27001 information security management systems | 2022, including Amendment 1:2024 ([iso.org](https://www.iso.org/standard/27001)) |
| `aicpa-tsc-2017` | AICPA Trust Services Criteria | 2017 with revised points of focus, 2022 ([aicpa-cima.com](https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022)) |
| `eu-cra-2024-2847` | Regulation (EU) 2024/2847 CRA evidence crosswalk | Official Journal text, 20 November 2024 ([EUR-Lex](https://eur-lex.europa.eu/eli/reg/2024/2847/oj)) |

```python
from rigor_foundry.compliance_maps import builtin_template, builtin_template_ids

print(builtin_template_ids())            # includes 'eu-cra-2024-2847'
template = builtin_template("iso-iec-27001-2022")
mapping = template.mapping_for("application-security")
print([reference.reference for reference in mapping.references])
```

Every template and standard descriptor is content-addressed with a SHA-256
digest and validates its own integrity on parse.

## Export boundary

`report_oscal` renders deterministic OSCAL 1.1.3 assessment-results JSON from an
effective profile lock, its per-control assessments, and one template. The
export is a boundary, not an attestation:

- each assessment becomes one OSCAL **observation** with the RigorFoundry status,
  domain, and assessment digest, plus one `related-control` property for every
  mapped external control identifier;
- `findings` and `risks` are omitted — RigorFoundry emits candidate observations,
  not attested findings or residual risk;
- `import-ap` references this documented boundary, not an authored OSCAL
  assessment plan;
- the metadata carries the non-certification notice and names every unsupported
  field explicitly.

Object identifiers are deterministic (RFC-4122 name-based UUIDs derived from the
input digests), so the same inputs always produce byte-identical output. A
`generated_at` UTC timestamp is required; the export never reads a wall clock.

```python
from rigor_foundry.compliance_maps import builtin_template
from rigor_foundry.oscal_export import export_digest, report_oscal

template = builtin_template("aicpa-tsc-2017")
document = report_oscal(lock, assessments, template, "2026-07-15T12:00:00Z")
digest = export_digest(lock, assessments, template, "2026-07-15T12:00:00Z")
```

The mapped standards remain the property of their publishers; RigorFoundry
references identifiers and editions only.
