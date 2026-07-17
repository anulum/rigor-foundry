# Public API stability

RigorFoundry inventories every name in the package-level `rigor_foundry.__all__`
under API-stability schema `1.1`. The authoritative machine-readable inventory
is returned by:

```python
from rigor_foundry.api_stability import public_api_manifest

manifest = public_api_manifest()
```

The result has sorted `stable` and `provisional` name arrays, exact stable
runtime-binding records, and structured `deprecated` records. Compatibility
tests require every top-level export to have exactly one classification. Every
stable binding is also checked for its exact canonical object identity, object
kind, implementation module, and qualified name, so retaining or spoofing a
spelling while rebinding it fails.

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

`AuditPolicy` is implemented by the cohesive `policy_models` owner, while the
established `rigor_foundry.models.AuditPolicy` import and runtime module identity
remain unchanged. This split is an internal ownership change, not a public API
migration.

Within the same major release, these names will not be removed or silently
rebound to an incompatible kind of object. Record fields and serialized
protocols retain their own explicit schema/version contracts; stable import
availability does not erase those migration boundaries.

## Provisional imports

`report_sarif`, `SARIF_SCHEMA_URI`, and `SARIF_VERSION` are provisional public
imports. Their emitted document is independently governed by SARIF 2.1.0 and
the explicit RigorFoundry property names documented in [SARIF export](sarif.md).

`RuleMaturityPolicy`, `RuleReviewEvidence`, `RuleMaturityAssessment`,
`RuleMaturityReport`, `RULE_MATURITY_SCHEMA_VERSION`,
`MATURITY_CASE_MANIFEST_SCHEMA_VERSION`, and
`evaluate_rule_maturity_manifest` are provisional. Their JSON contracts are
independently versioned at schema 1.0, and enforcement consumes their exact
content digest rather than treating top-level import stability as protocol
compatibility.

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
