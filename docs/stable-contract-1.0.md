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
