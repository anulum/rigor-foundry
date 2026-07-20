# 1.0 stable compatibility contract

RigorFoundry carries one digest-bound compatibility manifest for the proposed
`1.0.0` boundary. Retrieve it from an installed wheel without consulting the
source tree:

```console
rigor contract
```

or from Python:

```python
from rigor_foundry import stable_contract_manifest

manifest = stable_contract_manifest()
```

The current package version remains pre-1.0. The manifest is the frozen release
candidate contract; it becomes the published major-version commitment only if
the same contract is released as `1.0.0`. Its SHA-256 `contract_digest` covers
every field except the digest itself.

## What is frozen

The contract binds three different surfaces instead of treating package import
success as universal compatibility:

1. **Stable Python imports.** Eleven package-level names have exact runtime
   object, kind, module, and qualified-name checks. Other exported Python names
   remain explicitly provisional even when their serialized records are stable.
2. **CLI spellings.** Every currently installed command, option spelling, and
   positional name is in the stable CLI set. CI rejects a removed, renamed,
   added-but-unclassified, or silently changed parser surface. The installed
   command keeps the global exit boundary: `0` completed, `1` a candidate or
   policy gate did not pass, and `2` invalid input or unsafe/unavailable state.
3. **Serialized protocols.** Every persisted, signed, or interchange schema
   supported by the 1.0 candidate has an exact schema name and version. The
   list includes reports, reviews, policies, anchors, campaigns, packs,
   maturity, enforcement, offline verification, CRA evidence, SARIF, OSCAL,
   remediation, provenance, work records, and adapter evidence.

The manifest is authoritative for the exact command and schema inventory. The
human documentation for each command or schema continues to define semantic
preconditions, field meanings, authority boundaries, and failure modes.

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
1.0 candidate contract.

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
