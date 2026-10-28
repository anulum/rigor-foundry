# Rule declarations and original components

The provisional `RuleScope1`, `SemanticDecision1` and `AtomicRule1` records
represent exact source-bound declarations. They retain the original
`ConditionExpression` 1.1, `SourceSpan1`, `OwnerProof1` and `TypedObjectRef1`
contracts. They do not authenticate an issuer, accept semantic extraction or
admit a policy for execution.

Every parser and serializer requires an explicit `PolicyReadBudget1`.
Document bytes and container nesting are checked before child parsing;
collection owners also enforce source and aggregate reference limits. Inputs
with unknown fields, unsupported versions, reordered sets, duplicate identities,
invalid UTF-8 or incorrect digests refuse. For file input, use
`read_policy_document` from `rigor_foundry.policy_source_reads` before the
record's `from_dict` method. That reader also rejects duplicate JSON keys and
uses bounded stable file reads.

## Scope and exact statements

A global scope has no condition and explicitly lists every supported task
event. A scoped rule has an original condition and a nonempty sorted event
subset. Missing facts remain unknown under `evaluate_condition_state`;
structural scope parsing does not authenticate fact producers or decide a gate.

```python
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.rule_scope import RuleScope1
from rigor_foundry.task_context import TASK_CONTEXT_EVENTS

limits = PolicyReadBudget1.build(
    max_document_bytes=65536,
    max_source_bytes=65536,
    max_total_source_bytes=131072,
    max_sources=16,
    max_rules=64,
    max_references=1024,
    max_depth=32,
)
scope = RuleScope1.build(
    scope_kind="global",
    condition=None,
    events=tuple(sorted(TASK_CONTEXT_EVENTS)),
    budget=limits,
)
assert RuleScope1.from_dict(scope.to_dict(budget=limits), budget=limits) == scope
```

`AtomicRule1` hashes the statement's exact UTF-8 bytes, including whitespace
and original newline characters. Source spans retain their declared selection
order. Dependencies and decision IDs are sorted unique sets; a rule cannot
depend on itself. Component references sort by
`(kind, format_version, object_id)` and cannot give two digests to one identity.
Proposed, active, held, superseded and retired declarations remain explicit.
An active lifecycle string is not semantic acceptance.

`SemanticDecision1` retains the issuer, original spans, rationale, condition,
affected rules, successors and original owner proof. Its relations are
`supersedes`, `exception`, `exclusion`, `interpretation` and `adoption`.
Supersession has nonempty distinct directed rule sets. Complete graph resolution,
competent issuer authentication and exception permission remain required at the
consuming boundary; dates, filenames and matching hashes establish none of these.

## Original component resolution

`PolicyComponent1` and `resolve_policy_component`, from
`rigor_foundry.source_component_reader`, resolve these actual original owners:

| Reference kind | Format | Original model | Owning digest |
| --- | --- | --- | --- |
| `control-definition` | `1.0` | `ControlDefinition` | `control_digest` |
| `evidence-contract` | `1.0` | `EvidenceContract` | `contract_digest` |
| `evidence-reference` | `1.0` reference binding | `EvidenceReference` | `evidence_digest` |
| `review-attestation` | `2.0` | `ReviewerAttestation` | `attestation_digest` |
| `authority-clause` | `2.0` | `AuthorityClauseV2` | `clause_digest` |
| `freshness-policy` | `2.0` | `FreshnessPolicyV2` | `policy_digest` |
| `adapter-lock` | `1.0` reference binding | `AdapterLock` | `adapter_digest` |
| `reviewer-identity-policy` | `semantic-reviewer-identity-policy.v1` | `ReviewerIdentityPolicy` | `policy_digest` |

The original complete serialized objects are unchanged. The control identity is
its original `versioned_id`; the numeric evidence contract uses `contract_id`.
Authority and freshness use `clause_id` and
`policy_id`. No `object_kind` is inserted into these legacy objects.
The adapter uses its original `adapter_id` and all eight original fields,
including its tool version. Its reference format `1.0` identifies this fixed
binding; it adds no version header to the adapter itself. Unknown adapter fields
refuse before the original parser. The identity policy has no original object ID;
both reference ID and digest use its complete original `policy_digest`.
Its trust policy, key lifecycles and reviewer bindings remain unchanged.
Original evidence references have exactly eleven fields and no schema header.
Their fixed reader closes those fields before the unchanged original parser;
reference format `1.0` does not add a header. Original review attestations retain
all thirteen fields, schema `2.0` and the signature domain
`rigor-foundry.reviewer-attestation.v1`. Their complete attestation digest is
their reference ID; the separate signed reviewer identity may contain spaces.
Original control applicability, numeric freshness, independent reviewer count
and remediation obligations remain intact. A reference cannot appoint a loader
or turn a source metadata object into an enforcement component.

Resolution validates the complete supplied component cohort, including
unselected members, under count and aggregate byte limits. Missing targets,
duplicate identities, altered original digests and normalization of legacy input
refuse. Resolving a component establishes its structural identity, rather than
its signatures, current selection or accepted relation to an atomic rule.

## Explicit review and evidence contracts

`rigor_foundry.review_policy` provides provisional `ReviewRoleRequirement1`
and `ReviewPolicy1` records at version `1.0`. Each role binds an exact original
reviewer identity policy and an explicit independence requirement. A review policy
retains its mode (`independent`, `self-review` or `conditional-self-review`),
sorted unique roles, source rule IDs and named unavailability fact references.
Parsing these declarations does not appoint reviewers or establish that a manager
is unavailable. Empty declarations grant no fallback or approval. A consuming
assessment must verify actual role eligibility, source permission and authenticated
unavailability before allowing conditional SelfReview.

`rigor_foundry.evidence_contract_v2` provides `EvidenceRequirement1` at `1.0`
and `EvidenceContract2` at `2.0`. Each requirement retains an evidence type,
exact adapter reference, subject class and exact original freshness-policy
reference. A contract requires a nonempty sorted unique requirement set and an
explicit review-policy reference. Aggregate reference limits apply before child
parsing. The contract does not invent numeric freshness or reviewer counts;
legacy `EvidenceContract` records keep their original positive TTL, adapter and
evidence sets, and minimum independent reviewer count.

The new review and evidence records expose `build`, `to_dict` and `from_dict`
with an explicit read budget. `ReviewPolicy1.reference` and
`EvidenceContract2.reference` bind their complete owning digests. Resolve their
targets through the corresponding new owning parser; the original context-source
resolver does not acquire these formats merely because a typed reference parses.

## Rule-bound qualitative controls

`rigor_foundry.control_definition_v2.ControlDefinition2` is provisional at
`2.0`. It binds an explicit rule ID, original scope, require/deny mode, qualitative
evidence contract and unchanged original remediation contract. Domain, severity
and target maturity retain their existing vocabularies. It has no implicit
default applicability or separate legacy condition field.

`control.verify_rule_binding(rule, budget=limits)` accepts an actual
`AtomicRule1` and rechecks both complete records. Rule ID, mode and complete scope
must agree, and the rule must contain the exact control reference, including its
owning digest. The new boundary also closes the original remediation's seven
fields while preserving its exact text, order and obligations. Original
`ControlDefinition` `1.0` serialization remains unchanged.

Atomic enforcement references allow original control `1.0`, authority `2.0`
and freshness `2.0`, together with qualitative control `2.0` and review-policy
`1.0`. Bare adapters and reviewer identity policies are support dependencies;
they cannot become atomic enforcement components. Structural control binding
does not establish source acceptance, applicability, evidence validity or a gate
verdict.

## Original signed-pack bindings

`rigor_foundry.component_source_resolution.parse_policy_component_target`
resolves fourteen closed policy target formats: the eight original component
formats listed above; new `ControlDefinition2`, `EvidenceContract2`,
`ReviewPolicy1`, `EvidenceReference2` and `SemanticDecision1`; and original
`StandardPackV2` at `2.0`.
Each fixed branch compares the complete actual target reference, including its
original ID and owning digest. Unsupported pairs refuse before target parsing;
the context-source resolver keeps its separate supported subset.

`StandardPackSource2` bounds the complete original pack before its existing
recursive serializer/parser runs. It requires actual original child types and
immutable collections for direct instances, and exact arrays for wire input.
Control counts and aggregate references include every control, condition,
authority grantor and freshness invalidator. All original controls, child wires
and detached signature bytes remain present. Its reference uses original
`pack_id` and complete `pack_digest`; the original pack version remains inside
that digest. Reading a pack does not verify current trust or semantic acceptance.

`rigor_foundry.legacy_control_binding.LegacyControlBinding1` is provisional at
`1.0`. It binds a source rule to an exact original control `1.0` within an
original signed pack `2.0`, together with sorted unique source decision IDs.
`binding.verify_pack(pack, budget=limits)` revalidates the complete actual pack
and returns its exact matching original control. Empty packs, absent controls,
different owning digests and qualitative-control casts refuse. Original target
maturity, applicability condition/default, numeric freshness, reviewer count,
adapter/evidence requirements and remediation remain intact. This membership
check does not establish complete selected-control enumeration or permission
for an exception, waiver or gate approval.

## Qualitative freshness declarations

`rigor_foundry.freshness_proof` provides provisional `InvalidatorObservation1`
and `FreshnessProof1` at `1.0`. An invalidator retains `clear`, `invalid` or
`unknown` explicitly. `clear` requires an original `OwnerProof1`; a parsed proof
envelope still needs authentication by its installed current owner.

A freshness proof binds the exact original freshness-policy reference, mode,
independent subject digest, original subject proof, sorted unique invalidator
observations and subject snapshot. Its subject proof must match that digest
and snapshot. Invalidator owners retain their own source snapshots. No duration,
expiry or observation timestamp is inferred. Explicit legacy expiry and key or
grant lifecycle rules remain separate.

`proof.verify_policy_binding(policy, budget=limits)` requires an actual original
`FreshnessPolicyV2` and compares its complete identity, mode and invalidator set.
This checks structural binding. Invalid and unknown observations remain present;
the method does not authenticate `clear` or return a freshness verdict.
For every invalidator, the installed verifier must resolve its actual selected
owner, source contract and independent current observation, then establish that
the ID/state governs this outer subject and its relevant state or generation.
Missing, unrelated, contradictory, stale, revoked or unauthenticated observations
cannot establish `clear`; invalid and unknown cannot pass. Held source checks
remain required through use and closure.

The invalidator record's `observation_digest` includes its proof envelope.
The original owner's `observation_digest` hashes its independently observed
`ContextProducerObservation1` preimage. These digests are distinct; equating them
would introduce a circular proof.
`freshness_reference_count(value, budget=limits)` lets enclosing consumers bound
the complete nested allocation before parsing children. It counts the policy,
subject-proof pair, invalidator IDs and optional original proof pairs.

## Independent evidence subjects

`rigor_foundry.evidence_reference_v2.evidence_subject_digest` derives the closed
`evidence-subject` `1.0` identity before either included proof exists. It hashes
the exact adapter reference, artifact digest and byte count, configuration,
toolchain, cohort and complete sorted unique source-object references. No
producer proof, freshness proof or enclosing evidence digest enters this subject.

Provisional `EvidenceReference2` at `2.0` adds the evidence identity/type,
classification, opaque reference, validated UTC observation time, declared result,
original producer proof and qualitative freshness proof. Both included proof
subjects must match the independently computed evidence subject. Producer and
freshness owners may retain different source snapshots. Changed artifact, source,
configuration, toolchain or cohort identities cannot retain the old proof binding.
All nested reference allocations and source counts respect the explicit budget.

Results `pass`, `fail`, `unavailable` and `refused` remain declarations until the
installed adapter parses the actual retained artifact and current owners verify
its complete scope and proofs. Neither result text nor structural parsing grants
approval. The opaque `reference` field embeds no raw artifact or credentials and
does not grant permission to read a path or URL. `object_reference(budget=limits)`
returns its exact typed evidence identity, separately from that artifact reference.

`evidence.verify_requirement_binding(requirement, policy, budget=limits)` checks
the actual `EvidenceRequirement1`, adapter, evidence type, subject class and
original freshness policy. It supplies no assessment verdict. The original
numeric `EvidenceReference` keeps its exact separate wire and expiry semantics;
neither parser migrates the other format.

## Shared original assessment predicates

`rigor_foundry.assessment_evidence_validation` factors the existing legacy
predicates into three functions. They consume original validated contract,
adapter, evidence, attestation and trust-store inputs; they create no profile
or lock and grant no source selection or operational authority.

- `validate_original_evidence_bindings` requires one exact original adapter
  identity and owning digest for each reference, covering the control domain.
- `validate_original_pass_evidence` retains the original positive numeric age
  bound, explicit expiry, nonempty evidence and complete required adapter/type
  coverage. Every submitted item must be fresh; a fresh member cannot hide
  another expired or future observation.
- `validate_original_reviewers` retains actual Ed25519 verification of the
  exact original assessment body and decision, current review interval,
  explicit trust store and required distinct reviewer IDs, key IDs and public
  keys. The original case-sensitive identity comparison remains unchanged.

The existing public `ControlAssessment` now calls these same predicates. Its
wire `1.1`, original review-body identity, status/applicability, waiver and
limitations rules remain unchanged. New selected consumers must supply their
own actual selected source/control relations and independently derived review
body; these functions do not appoint owners or infer SelfReview permission.

## Complete quality projection

`rigor_foundry.quality_projection_v3.QualityProjectionRowV3` retains an exact
control reference, source rule IDs, scope, evidence contract, reviewer policy,
target maturity and applicability decision references. Its format is `3.0`.

The `legacy1` case binds the actual original control and numeric evidence
contract at `1.0`. It preserves the original Boolean `default_applicable`,
nullable original condition and target maturity; `review_policy` is null
because the original positive reviewer count remains in the evidence contract.
The `qualitative2` case binds the actual qualitative control and evidence
contract at `2.0`, with its explicit review-policy reference. Its default and
condition are null because its `RuleScope1` owns applicability.

`row.verify_control_binding(control, budget=limits)` reparses the actual complete
owning control and compares every projected obligation. Qualitative rows also
retain the control's exact scope and source rule relation. Rehashing a row cannot
repair a different control digest, evidence contract, review policy, maturity or
original applicability field.

`validate_quality_projection(rows, controls, budget=limits)` requires exactly
one complete row per supplied selected control, sorted by its exact versioned
identity. It validates both actual control generations and the complete cohort,
including aggregate reference counts and encoded array bytes. Missing, extra,
duplicate or reordered rows refuse. The enclosing owner must derive the supplied
controls from its actual selected signed generation; this structural check
does not establish selection or evaluate applicability.

Applicability decisions use exact `SemanticDecision1` references at `1.0`.
`decision.reference(budget=limits)` binds the complete declaration's original
ID and digest; the fixed policy target resolver reparses its actual owner.
Issuer authentication, source acceptance and permission for exceptions remain
separate required checks. None of these APIs supplies a gate verdict.

## Selected assessment inputs

`rigor_foundry.selected_control_assessment_v2.SelectedControlAssessment2` uses
the exact `2.0` wire. It binds the selected lock, quality projection, task and
event request digests; the actual control generation; explicit applicability
and status; evidence and review references; assessor, timestamp and reason.
`legacy1` references original evidence at reference format `1.0`; `qualitative2`
references `EvidenceReference2`. Both retain the actual original signed review
attestation format `2.0`. Reference identities are sorted and unique under
complete byte and allocation bounds.

Applicability is the string `true`, `false` or `unknown`, separately from any
legacy Boolean default. Unknown cannot pass, and false remains explicitly
unassessed. A declared status, including `pass` or `accepted-risk`, supplies no
authentication or gate result. Current contract, evidence, reviewer and exact
source exception verification remain the installed consumer's responsibility;
accepted risk cannot replace a mandatory source floor's pass.

`assessment.verify_quality_binding(row, control, budget=limits)` verifies the
actual complete quality row and owning control generation. The enclosing owner
must independently derive the complete selected cohort and verify the lock,
projection, task and request identities; coordinated subsets of the row/control
inputs cannot prove that completeness.

`assessment.review_body_digest(budget=limits)` hashes every assessment field
except `reviews` and the final `assessment_digest`. Reviews can therefore sign
the independent complete input before their references are added. Changing a
lock, projection, task or request changes that body; adding the resulting review
references changes the final assessment digest without changing its review body.
Original Ed25519 attestations keep their original signature domain, exact body
binding and validity checks. A digest or parsed signature alone authenticates
neither a reviewer nor a selected generation.

`validate_selected_legacy_pass` consumes the exact selected assessment, quality
row and original control alongside complete original adapter, evidence and
attestation cohorts, an explicit original public trust store and an aware
evaluation instant. It revalidates all complete owners, matches the declared
evidence/review references and applies the same original numeric freshness,
adapter/type coverage and positive independent reviewer predicates used by
`ControlAssessment`. Actual original Ed25519 signatures bind its independently
derived review body. Missing trust, self review, insufficient distinct quorum,
stale/future/expired evidence and changed request bodies refuse. No v1 lock is
created. Complete selected-root/source custody, artifact/result observation,
key lifecycle and closing verification still belong to the installed consumer.

Supporting evidence contracts, evidence references, reviewer identity policies,
attestations, adapter custody and semantic decisions cannot become atomic
enforcement components merely because their fixed target readers exist.

## Complete declared rule graphs

`rigor_foundry.source_semantic_graph.source_rule_dependency_order` revalidates
the complete sorted rule and semantic-decision cohorts. It resolves every
declared dependency, decision and affected/successor target, including held and
historical rows. A rule's decision reference must actually name that rule in
the decision's affected or successor set. Endpoints are checked even when the
rule has no redundant backlink; an empty source-only decision creates no rule.

The complete declared dependency relation and the complete declared `supersedes`
relation must both be acyclic. Conditional decisions and inactive lifecycle
labels cannot hide a declared supersession cycle. Interpretation, adoption and
exclusion metadata do not become supersession edges. Directed set expansion
has an allocation bound before any Cartesian edge set is materialized.

The returned IDs contain every supplied rule exactly once, after its
dependencies. Simultaneously available nodes sort by exact ID; this ordering
does not select semantic precedence. Complete encoded metadata bytes, source
counts and declared reference allocations are bounded across both cohorts.

The installed owner must still authenticate the actual complete source cohort,
issuer competence, scope and current condition facts; independently derive all
effective decisions; check simultaneous conflicts and prove exception authority.
Caller-selected omissions or a successful graph traversal establish none of
those requirements and grant no gate result.

The [retained source universe](source-universe.md) separately verifies the
complete host-selected original source cohort and byte partitions. Neither that
byte accounting nor these declaration records establish semantic completeness.
Source access, issuer decisions, corpus acceptance, current host selection and
permission for effects remain separate owning checks.

## Deterministic source document inputs

`rigor_foundry.rule_source_document.RuleSourceDocument1` retains the complete
source universe, original byte regions, atomic rules, semantic decisions,
qualitative controls, review policies, legacy control bindings, original
freshness policies and authority references. Each collection has a fixed child
owner; extra fields, duplicate identities, mutable direct collections and changed
child digests refuse. Original children keep their complete original wire.

Collections sort by their exact identities. Regions retain `(source_id,
start_byte)` order. Legacy bindings use the composite `(rule_id, pack.object_id,
control.object_id)`: a rule may bind multiple original controls and an original
control may have several source rules. Repeated triples refuse even when their
binding digests differ. Digest ordering never selects a different convention.

Explicit aggregate reference, byte, collection and nesting limits cover the
whole document, including its envelope and final digest. Original region links,
source counts and freshness invalidators are bounded before their original
child parsers allocate the corresponding records. The separate
`compiler_contract_digest` identifies the compiler contract input. Serialization
adds no timestamp, resulting pack/profile/lock, signature or corpus acceptance.
The document digest hashes every other complete listed field deterministically.

`from_dict` checks bounded structural integrity; it does not resolve external
typed targets, accept source extraction or authenticate semantic decisions.
The consuming compiler must still verify the complete original source cohort,
same retained bytes and region/span joins, all component and decision relations,
original pack membership and actual source/issuer/corpus acceptance. A
structurally valid document supplies none of those permissions by itself.

## Source compilation with retained owners

`rigor_foundry.rule_source_compiler.compile_rule_source_document` takes the
existing `SourceUniverseOwner` and complete explicit rule, region, decision and
component cohorts. It obtains the universe from that actual owner. There is no
caller-supplied replacement universe, filesystem discovery or prose interpreter.
Repeated compilation of the same complete inputs and held owner state is
identical; the compiler adds no timestamp or resulting selection.

`rule_source_compiler_contract_digest()` separately identifies the document
schema, fixed target table, composite legacy order, complete declared graph,
component joins and retained source checks. This contract identity is separate
from the document digest, actual implementation custody and semantic acceptance.

`verify_rule_source_document` revalidates the complete document and returns all
rule IDs in dependency-first order. It verifies the actual complete source
cohort initially, resolves every supplied external component through its fixed
owning parser, and rejects inconsistent versioned target identities even in
unused support objects. Whole target bytes and typed-reference counts are
bounded together with the document. Original pack members and their nested
numeric evidence contracts keep their actual original identities.

Every rule component must be declared by the complete emitted cohort, and every
emitted component has an owning rule. Active rules require enforcement
components and a declared normative source region. Qualitative controls retain
exact rule/scope/mode bindings; their evidence references resolve the actual
inline review/freshness policies, exact adapter and matching subject class.
Review policy source-rule IDs equal the rules that actually reference it.
Required reviewer identity policies resolve as complete original objects.

Legacy bindings verify the exact original pack member. All controls, authority
clauses and freshness policies of each referenced original pack remain
accounted for; a valid pack signature cannot excuse a dropped control. Signature
bytes, old numeric evidence and original conditions are preserved. Parsing
these records does not authenticate current signing trust or transition scope.

Source/region/rule/decision links resolve in both directions. Every citation
has an overlapping declared same-source region, and every region's declared
rule/decision has a matching citation. Half-open byte intervals do not overlap
at adjacent endpoints. Lookup uses indexed source relations and sorted interval
indexes without rewriting the retained citation order. Duplicate span IDs must
refer to identical complete spans. Rule output classification cannot be less
restricted than its cited source.

The same actual source owner finally verifies complete byte partitions and
original span bytes, including closing source and implementation checks. Held
or excluded sources cannot supply included citations. A source-only exclusion
can retain an explicit exclusion decision without inventing a rule endpoint;
that declaration still needs actual competent issuer and corpus acceptance.

The result remains a compiled source candidate. Declared byte overlap does not
prove adequacy of the extracted prose. Competent issuer/effective decision
verification, independent corpus/native ratification, current root selection,
evidence authentication, gate evaluation and effect authority remain separate
required owning boundaries.
