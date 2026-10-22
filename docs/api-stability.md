# Public API stability

RigorFoundry inventories every name in the package-level `rigor_foundry.__all__`
under API-stability schema `1.1`. The authoritative machine-readable inventory
is returned by:

```python
from rigor_foundry.api_stability import public_api_manifest

manifest = public_api_manifest()
```

The broader 1.0 Python, CLI, and serialized-schema boundary is exposed
by `rigor contract` and documented in the
[1.0 stable compatibility contract](stable-contract-1.0.md). Source metadata
declares package version `1.0.0`. The manifest describes compatibility; release
authorisation and registry availability require separate evidence.

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
- `stable_contract_manifest`
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

`ExternalSourceClaim`, `SourceRetrievalPolicy`, `SourceCapture`,
`SourceVerification`, `SOURCE_PROVENANCE_SCHEMA_VERSION`,
`read_source_payload`, `source_provenance_to_json`, and
`verify_external_source` are provisional. Their schema 1.0 records distinguish
declared retrieval metadata from publisher authority and bind claim, policy,
capture, and successful offline verification through separate digests.

`VerificationBundle`, `EvidenceEntry`, `DetachedEvidenceSignature`,
`ReviewEvidence`, `ModelAliasEvidence`, `OfflineTrustPolicy`,
`VerificationKeyPolicy`, `EvidenceVerificationResult`,
`OfflineVerificationReport`, `verify_evidence_bundle`, and their schema/domain
constants are provisional Python imports. The installed `rigor verify` command
and its schema-1.0 bundle/trust-policy/result contracts form the stable offline-verification CLI
boundary. See [Offline evidence verification](offline-verification.md).
The v1 verification-key wire remains closed and unchanged. Explicitly supplying
`enrolled_identity` selects a separate v2 key record for semantic signing roles;
its identity is included in the key-policy digest.
Existing `semantic_reviewers` policies containing v1 records are refused by the
five-role builder. Reissue those records with selected identities and update
their changed policy digest in the host's expected selection. Construct
`RuleChainV2TrustRoles` through its keyword builder: the author policy is a new
required role, and positional dataclass construction is not a migration route.

The module-level `signed_clause_semantics_set_v2.SignedClauseSemanticsSetV2`
parser and verifier are provisional Python APIs. They authenticate an exact
semantics body with separate author and reviewer signatures without granting
adoption or effect authority. See [Canonical clause semantics](clause-semantics.md).

The module-level clause-semantics binding, constraint-evaluator registry,
authority-requirement and owner-confirmation APIs are provisional. The binding
retains the current digest-only authority-clause wire. Native ratification-source
verification supports the explicitly selected Claude JSONL format and produces
an integrity-only proof. None of these APIs adds a stable package-level export
or effect-admission authority. See [Canonical clause semantics](clause-semantics.md).

The module-level `rule_chain_candidate.inspect_rule_chain_candidate` and
`RuleChainCandidateReport` are provisional read-only Python APIs. They are not
package-level exports in the frozen 1.0 compatibility inventory and do not
admit a selected lock or an effect. See [Rule-chain candidate inspection](rule-chain-candidate.md).

Every other current `rigor_foundry.__all__` name is explicitly provisional.
These APIs remain typed, documented where public, and covered by
production-boundary tests. A minor release may refine or remove a provisional
import after an explicit changelog entry. Any independently frozen serialized
protocol retains its own compatibility and migration requirements.

The module-level signed-acceptance, v2 candidate, effective-lock, selected-chain
and selected-semantics APIs are also provisional. Their full runtime dependency
chain is documented in [Rule-chain candidate inspection](rule-chain-candidate.md)
and [Canonical clause semantics](clause-semantics.md). They add no package-level
exports or stable CLI dispatch path. Existing v1 pack/profile/lock wires and the
current digest-only `AuthorityClauseV2` remain unchanged.

The module-level `condition_facts.ConditionFact`, `ConditionTruth` and
`condition_evaluation.evaluate_condition_state` APIs are provisional. They
evaluate supplied known, absent and unknown observations without changing the
existing `ConditionExpression`1.1 Boolean behavior. The provisional module
command `python -m rigor_foundry.condition_evaluation_cli` uses its own explicit
operand/result versions and is outside the frozen `rigor`1.0 command inventory.
It never authenticates fact provenance or grants effects. See
[Conditions with partial observations](condition-evaluation.md).

Compatibility requires explicit selection of the new signed acceptance and
host-state records. Identity-bearing reviewer key enrollment must agree with
its identity binding; case aliases cannot occupy separate reviewer bindings.
The existing semantic-source proof wire retains its fields: the new consumer
checks the nested discovery selection on its held source state. The interim
scope resolver explicitly refuses profiled registries instead of interpreting
their layout with fixed v1 paths. Path-root derivation uses the explicit roots
in either canonical registry schema.

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
deprecation window. There are no deprecated stable top-level imports in the
frozen 1.0 contract.
