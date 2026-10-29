# 1.0 stable compatibility contract

RigorFoundry carries one digest-bound compatibility manifest targeting
`1.0.0`, the version declared by the current source metadata. Retrieve it from
an installed wheel without consulting the source tree:

```console
rigor contract
```

or from Python:

```python
from rigor_foundry import stable_contract_manifest

manifest = stable_contract_manifest()
```

Source version, compatibility target and publication state are separate. The
manifest defines the frozen contract in this source tree. Publication requires
the release gates and explicit owner authorisation; verify an installable
version in the [public registry](https://pypi.org/project/rigor-foundry/). Its
SHA-256 `contract_digest` covers every field except the digest itself.

## What is frozen

The contract binds three different surfaces instead of treating package import
success as universal compatibility:

1. **Stable Python imports.** Eleven package-level names have exact runtime
   object, kind, module, and qualified-name checks. Other exported Python names
   remain explicitly provisional even when their serialized records are stable.
2. **CLI spellings.** Every currently installed command, option spelling, and
   positional name is in the stable CLI set. CI rejects a removed, renamed,
   added-but-unclassified, or silently changed parser surface.
3. **Serialized protocols.** The manifest names exact schema identifiers
   and versions, including reports, reviews, policies, anchors, campaigns,
   packs, maturity, enforcement, offline verification, CRA evidence, SARIF,
   OSCAL, remediation, provenance, work records, and adapter evidence. An AST
   guard requires every production `*_SCHEMA_VERSION` declaration to have an
   explicit classification: frozen, version-pinned provisional, or individually
   justified outside the frozen interchange. A serializer/parser using a bare
   string `schema_version` cannot evade the named inventory. Host-held proofs,
   private coordination formats, aliases and provisional candidate records
   outside the frozen set are named with their reasons in the test contract.

The manifest is authoritative for the exact command and schema inventory. The
human documentation for each command or schema continues to define semantic
preconditions, field meanings, authority boundaries, and failure modes.

The identity-bearing semantic key-policy wire at version `2.0` is explicitly
provisional and separately version-pinned. The frozen
`verification-key-policy` wire remains `1.0` with its original fields.
Supplying an enrolled semantic identity selects the new record and changes
its digest; this does not change the frozen manifest or enroll a live key.
See [public API stability](api-stability.md) for the consuming role boundary.

The inventory-domain, inventory-baseline, maintained-surface, maintained-inventory,
fact-observation, fact-context, task-context and remediation-task-binding
declarations are explicitly provisional at `1.0` and individually version-pinned.
They do not extend the frozen manifest. Their source verification and authority
boundaries remain defined in [maintained contexts](maintained-context.md) and
[task contexts](task-context.md).

The `source-universe-entry` declaration is also explicitly provisional at
`1.0`, individually version-pinned outside the frozen manifest. Its
[actual source owner](source-universe.md) reuses existing original HTTPS
capture, native pin and discovery receipt formats without changing their
versions, fields or owning digests.

The [explicit rule declarations and qualitative contracts](common-policy.md)
are also individually version-pinned provisional schemas. `RuleScope1`,
`SemanticDecision1`, `AtomicRule1`, `ReviewRoleRequirement1`, `ReviewPolicy1`
and `EvidenceRequirement1` use `1.0`; `EvidenceContract2` and
`ControlDefinition2` use `2.0`. They do not change the frozen manifest.
The new original-component reader retains existing control, numeric evidence, authority, freshness,
adapter and reviewer identity-policy bytes and owning digests. An adapter's
reference-only format binding does not add a schema field to the original wire.
`LegacyControlBinding1` is separately version-pinned provisional at `1.0`.
Its bounded original-pack reader retains the complete original `StandardPackV2`
`2.0` wire and signature; the membership relation does not migrate legacy controls.
`InvalidatorObservation1`, `FreshnessProof1` and the independent evidence-subject
preimage are separately version-pinned provisional at `1.0`;
`EvidenceReference2` is provisional at `2.0`. Their actual original owner proofs
and freshness policies keep their existing wire versions. The original numeric
evidence reference and assessment consumers remain unchanged.

`PolicyHold1` is separately version-pinned provisional at `1.0`. Its exact
seven-field declaration preserves bounded hold provenance; parsing does not
authenticate applicability, clear a hold or admit a selected policy.

`QualityProjectionRowV3` is separately version-pinned provisional at `3.0`.
Its original and qualitative cases preserve their actual control generations;
complete row/control binding does not select a lock or authenticate decisions.
`SelectedControlAssessment2` is separately version-pinned provisional at `2.0`.
Its original evidence reference binding `1.0` adds no legacy schema header;
review-attestation references keep schema `2.0`, the original complete owning
digest and the unchanged `rigor-foundry.reviewer-attestation.v1` domain.

## Compatibility rules

- A published schema identifier is never reinterpreted. An incompatible wire
  change requires a new identifier, an explicit migration, and a retained old
  reader for the supported major line.
- Stable Python names and CLI spellings are not removed or incompatibly rebound
  within the 1.x line.
- A stable surface must remain available while deprecated. Removal within the
  same major line requires at least two intervening minor releases; an explicit
  new major may remove it.
- Additive CLI options, commands, schemas, and stable Python names still require
  an intentional contract update and compatibility review. They are not
  admitted by parser drift.
- Provisional Python imports require an explicit changelog entry before an
  incompatible change. Consumers should pin the package and the relevant
  schema rather than infer stability from importability.

There are no deprecated stable Python imports or CLI commands in the frozen
1.0 contract.

## Boundaries

Compatibility is not correctness, legal conformity, or operational authority.
The contract does not turn a candidate into a defect verdict, make CRA evidence
an authority submission, authorise remediation or fleet activation, or make an
unavailable dependency pass. Schema compatibility also does not override
signature, digest, freshness, trust-policy, or exact-Git-object checks.

The contract intentionally says nothing about GitHub-hosted runner image or
`setup-python` artifact provenance beyond the repository's existing pins. That
external residual remains separately tracked and cannot be closed by a local
manifest.
