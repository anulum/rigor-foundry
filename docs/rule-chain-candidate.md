# Rule-chain candidate inspection

`rigor_foundry.rule_chain_candidate.inspect_rule_chain_candidate` is a
read-only Python API for checking whether one proposed semantic transition,
its signed review, retained StandardPack sources, and a signed ProjectProfile
refer to the same exact objects. It composes the host-selected discovery and
native-source readers, review verifier, pack verifiers, and profile selection.
It does not fetch a remote source or assign a numeric freshness lifetime.

The caller supplies the exact proposal artefact and source captures, typed v2
pack and profile objects, a host-composed semantic-review verifier, one
host-composed retained-source verifier per selected pack, the role-separated
trust policies, the expected project and scope, and an explicit UTC instant.
The host must protect selections and revocations throughout its leases. A
caller-controlled test provider can exercise the API but cannot enrol live
authority. A signed `clear` review is checked as a source dependency; the
reviewer must have a separate identity and trusted signing key from the author.
Role construction now explicitly supplies `semantic_authors` and
`semantic_reviewers` alongside the three existing rule-chain policies. Semantic
key records carry caller-selected, digest-bound v2 identities; the three other
roles retain v1 records. All role key material is distinct, and semantic author
and reviewer identity sets are disjoint ignoring case. The host still
authenticates the selected review identities and exact expected objects. The
review verifier additionally binds the named reviewer to its exact enrolled key
identity and requires the named author to belong to the selected author policy,
using case-insensitive enrollment comparisons. The role policies' disjointness
then prevents a named author from holding a reviewer key.

The result is `RuleChainCandidateReport`. Its digest binds the proposal,
review acceptance dependency, profile, packs, selected authority clauses and
reviewer policy. `guard_admissible` is always `False`. A report is neither a
signed EffectiveProfileLock nor an active dispatch permit. It cannot resolve
local constraints, current grants, adapter custody, revocation or mutable
evidence state, and it cannot authorise an effect. The v1 pack, profile,
audit-lock and dispatch formats remain unchanged; no automatic CLI or Guard
cutover occurs.

Applications that need an active gate must separately implement and select a
reviewed effective lock, verify current state and grant authority before each
effect, and obtain rollout authority. Reusing this inspection result as an
effect permission is a contract violation.

## Signed acceptance and selected v2 locks

`semantic_transition_acceptance_v2.SignedSemanticAcceptanceV2` binds a
complete `accepted-semantic-transition.v2` body to an external reviewer
Ed25519 signature in domain `rigor-foundry.semantic-transition-acceptance.v2`.
The body records exactly four successor links, statement hashes, discovery
selection and byte budgets, author attribution, source and native ratification
hashes, reviewer identity and declared review time. Envelope parsing recomputes
digests; `verify_signature()` checks the real signature, current key lifecycle,
attribution relation and distinct author/reviewer identities.

`ReviewerIdentityPolicy` binds every selected key to exactly one reviewer.
Identity uniqueness and enrollment agreement both ignore case. A v2 enrolled
key cannot be relabelled; legacy v1 keys retain explicit mappings in this data
API, while the five-role v2 chain requires identity-bearing semantic policies.
`ProposalAuthorAttribution` records selected attestation evidence and a
canonical session UUID; its digest does not authenticate the attesting host.

`HostSemanticAcceptanceVerifierV2.verify()` reads the selected policy,
revocations, review and native source under a host lease. It checks the
discovery digest on the same held semantic-source state that the existing
source verifier consumes. It also compares the retained findings bytes and
the exact four source spans. The returned dependency has
`guard_admissible == False`. Native human-origin markers and capture integrity
remain subject to the source-custody limits in
[canonical clause semantics](clause-semantics.md).

`rule_chain_candidate_v2.inspect_rule_chain_candidate_v2()` joins that
acceptance with the signed packs and profile, requiring four exact selected
successors and the current five role policies. `RuleChainCandidateReportV2`
is a read-only report; it does not select a lock.

`rule_chain_lock_v2.EffectiveProfileLockV2` carries a complete signed
projection: selected clauses and freshness policies, constraints, exclusions,
adapter custody, issuer order, acceptance selection, effect-operation catalogue
and resolver-code pins. Its `body()` and `build()` APIs validate and bind
the complete projection. Parsing and signature attachment establish integrity;
`verify_structural_lock()` additionally checks the current signed chain,
retained sources, adapter records, selected preconditions and active resolver
signature. Held locks retain blocking contradictions and refuse effective
verification. The `body()` signature remains on the public class; its
implementation is inherited from an internal projection owner.

`selected_rule_chain_host_v2.HostSelectedRuleChainVerifierV2` freshly
rebuilds the acceptance and candidate before trusting a selected lock.
`verified_lease()` repeats those checks after the consumer and refuses a
changed closing proof. The host provider pins state and revocations for the
entire context and authenticates their custody. A caller-created provider
demonstrates behavior without establishing operational trust.

## Closed first-operation dependencies

`ExtractorRegistryV2` and `AdapterOperationsV2` accept only their empty
bootstrap bodies or the fixed atomic-replacement candidate. The three declared
extractor entrypoints are present in `rigor_foundry.tier0_builtin`:
`extract_content_byte_count.extract`, `extract_fixed_variant.extract` and
`extract_path_target.extract`. Registry module names are metadata, not a
dynamic loader or proof of installed code identity.

`AtomicFileReplaceInvocationV2.from_bytes()` parses a closed canonical wire
for `local-file-write.atomic-replace`: requested path, standard canonical
base64 content, and separate declared target, count and variant. Decoded
replacement content is at most 16 MiB; each path is at most 4095 UTF-8 bytes.
`extract_atomic_file_replace_v2()` compares all declarations with the actual
content length, fixed `replace-or-create` variant and host-canonicalized path.
A supplied callback is an observation interface, not an admission capability.

`derive_selected_path_scope_v2()` derives current project/group roots from
exact selected registry bytes, including inactive registrations; the selected
project must be active. It accepts explicit profiled roots and performs no
filesystem lookup. Historical aliases do not become current registered roots.
`extract_atomic_file_replace_for_scope_v2()` uses that selected scope through
real descriptor-backed no-follow path admission. Linux x86-64 `openat2`
refuses symlinks, traversal, mount crossings during target descent, repository
internals and nested or unregistered repositories. Missing final leaves may be
created; their parent must exist. All observations and descriptors close before
the extraction call returns, and every failure becomes a chained
`PermissionError`. The direct callback API propagates callback errors.

These APIs extract and verify read-only dependencies. They install no handler,
write no replacement file, grant no permit and change no stable CLI or v1
serialized contract. Actual execution still requires protected installed-code
custody, current action applicability, grants, permits and final revalidation.
