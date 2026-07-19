# API and schema compatibility rules

Rule-pack `rigor-foundry/1.16.0` adds the bounded `api-compatibility` category
(prefix `AA`). Its findings are anchored **needs-evidence candidates**, not a
claim that a public change is breaking or that semantic versioning was
violated.

## Rule

| Rule | Signal | Confidence |
| --- | --- | :---: |
| `AA001-unbound-api-manifest` | a module-level literal Python `__all__` surface is absent from, differs from, or cannot be resolved against the tracked root manifest | high |

AA001 compares Python modules below the configured production source roots
with the fixed repository-root path `rigor-public-api.json`. It recognises one
direct module-level assignment or annotated assignment whose value is a list
or tuple of unique Python identifiers. The names are normalised into sorted
order before comparison. Function-local and class-local declarations are not
public module surfaces.

Mutation, repeated assignment, computed values, unpacking, non-string members,
duplicates, and invalid identifiers make a declaration dynamic. Dynamic
surfaces remain review candidates because a static scanner cannot bind their
runtime value. Syntax-invalid Python remains outside AA001; the applicable
parser or test-authenticity rule owns that condition.

The mutation signal is deliberately syntactic and bounded. It recognises
direct name, attribute, and subscript writes; mutable-sequence operations;
and expressions evaluated in decorators, defaults, annotations, class bases,
and class keywords. Deferred function/lambda bodies, class-local declarations,
lazy PEP 695 aliases, and indirect mutation through reflective helpers or
aliases are outside this signal. `from __future__ import annotations` is
honoured so deferred annotation text does not become a false candidate.

## Manifest schema

The tracked JSON document uses schema `1.0` and accepts no additional fields:

```json
{
  "schema_version": "1.0",
  "surfaces": [
    {
      "exports": ["AuditReport", "scan_repository"],
      "path": "src/example/__init__.py"
    }
  ]
}
```

Surface paths must be sorted, unique, canonical repository-relative POSIX
paths ending in `.py`. Export arrays must be sorted and unique, and every
member must be a Python identifier. A malformed or non-text manifest, a
recorded row without a corresponding declaration, and a declaration without a
recorded row each fail closed as separate candidate states.

A repository with neither a tracked manifest nor a qualifying declaration is
outside the rule's applicability and receives no AA001 candidate. A matching
manifest is also quiet. AA001 never interprets arbitrary source edits as API
changes.

## Evidence and review

Candidate evidence records state, counts, file identity, and canonical
SHA-256 surface identities. It does not copy export names or source excerpts.
The candidate anchor binds either the exact declaration blob and line span or
the exact manifest/repository state.

Reviewers should identify downstream compatibility requirements and decide
whether the observed surface is intentional. Update `rigor-public-api.json`
only after that review; a matching edit closes manifest drift but does not by
itself establish backward compatibility. Runtime attributes, signatures,
serialized schemas, native ABIs, re-export behavior without `__all__`, and
non-Python languages require their own evidence controls.

AA001 contributes the portable control for
`api-abi-schema-compatibility`. It enters maturity probation and cannot drive
enforcement until cross-repository adjudication and reviewer-effort evidence
satisfy the configured maturity policy.
