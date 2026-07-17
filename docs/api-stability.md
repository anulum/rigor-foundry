# Public API stability

RigorFoundry inventories every name in the package-level `rigor_foundry.__all__`
under API-stability schema `1.0`. The authoritative machine-readable inventory
is returned by:

```python
from rigor_foundry.api_stability import public_api_manifest

manifest = public_api_manifest()
```

The result has sorted `stable` and `provisional` name arrays plus structured
`deprecated` records. Compatibility tests require every top-level export to
have exactly one classification and to resolve to a real package attribute.

## Stable imports

The current stable top-level import names are:

- `AuditPolicy`
- `AuditReport`
- `Candidate`
- `GitTrustPolicy`
- `ReviewRecord`
- `__version__`
- `report_markdown`
- `review_templates`
- `scan_repository`
- `validate_reviews`

Within the same major release, these names will not be removed or silently
rebound to an incompatible kind of object. Record fields and serialized
protocols retain their own explicit schema/version contracts; stable import
availability does not erase those migration boundaries.

## Provisional imports

Every other current `rigor_foundry.__all__` name is explicitly provisional in
version `0.1.1`. Provisional does not mean untested: these APIs remain typed,
documented where public, and covered by production-boundary tests. It means a
minor release may refine or remove the import after an explicit changelog entry
while the project remains pre-1.0.

Consumers that need a provisional name should pin an exact RigorFoundry
version and test the relevant schema or behavior rather than inferring
compatibility from package import success.

## Deprecation contract

A stable name must remain exported while deprecated. Its lifecycle record must
name:

- the final semantic version that introduced the deprecation;
- a different classified replacement, when one exists; and
- a final semantic version no earlier than two minor releases later within the
  same major line. A new major version may perform the removal explicitly.

Compatibility tests reject duplicate or overlapping classifications,
unclassified exports, classifications for absent names, non-final semantic
versions, self-replacements, missing replacements, and a too-short same-major
deprecation window. There are no deprecated top-level imports in `0.1.1`.
