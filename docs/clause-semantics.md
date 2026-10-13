<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Apache License 2.0; see LICENSE. -->
<!-- © Concepts 1996–2026 Miroslav Šotek. All rights reserved. -->
<!-- © Code 2020–2026 Miroslav Šotek. All rights reserved. -->
<!-- ORCID: 0009-0009-3560-0851 -->
<!-- Contact: www.anulum.li | protoscience@anulum.li -->
<!-- RigorFoundry — canonical clause semantics -->

# Canonical clause semantics

`ClauseSemanticsSetV2.from_bytes` parses a canonical UTF-8 JSON body for one
project. The closed `rigor.clause-semantics-set.v2` format records clause and
statement digests, predecessor and projection references, scope, vocabulary,
target-table and evaluator-registry digests, and the resolver version.
It accepts six subjects: `admit`, `veto`, `rate`, `window`, `route` and
`precondition`. Each subject has its own exact field set.

```python
from rigor_foundry.clause_semantics_set_v2 import ClauseSemanticsSetV2

body = ClauseSemanticsSetV2.from_bytes(retained_body_bytes)
body_digest = body.body_digest
independent_mapping = body.to_dict()
```

The digest is SHA-256 of the exact accepted bytes. `to_dict()` returns a fresh
mapping; changing it leaves the retained body unchanged. Duplicate JSON keys,
noncanonical encoding, unknown fields, duplicate clause entries, unsorted scopes,
placeholder targets and invalid constraint parameters raise `ValueError`.

Rate constraints count operation intents and require integer limits and windows.
Time constraints use ordered, nonoverlapping UTC weekday ranges. Route constraints
use explicit provider, account reference, decimal cost ceiling and privacy class.
Preconditions and evaluator identifiers come from fixed sets.

`EffectVocabularyV2` retains the fixed thirteen effect classes.
`EffectTargetTableV2` binds those classes to fifteen target-kind rows. Their
`build()` and `from_bytes()` APIs verify the fixed version's canonical content
and digest; changed mappings require another reviewed version. Use `contains()`,
`allows()` and `triples_for_class()` to inspect the mapping.

Scope syntax validation recognises canonical paths, repository paths, remotes,
endpoints, hosts and project/group selectors. Path globs are limited to full
segments in exclusions; veto scopes cannot hide a glob exclusion.
`bind_clause_scope_groups_v2()` separately checks owning and foreign inbox groups
against the caller's selected registry group set.

These APIs validate data. Digest references are checked for format here;
matching them to retained objects, checking effect applicability, authenticating
signatures and current registry custody belong to their consuming verifier.
Parsing a body or passing a group set grants no permission to execute an effect.
The body parser is unsigned, and this API does not change CLI or fleet enforcement.

## Author and reviewer signatures

`SignedClauseSemanticsSetV2.from_bytes()` pairs the exact canonical body with
two `RuleChainV2Signature` envelopes. The author signs object kind
`clause-semantics-set-author` in domain
`rigor-foundry.clause-semantics-set-author.v2`; the reviewer signs object kind
`clause-semantics-set` in domain `rigor-foundry.clause-semantics-set.v2`.
Both envelopes must name the parsed body's digest. Parsing validates their
shape and binding; call `verify(roles=selected_roles, now=utc_instant)` to
check real Ed25519 signatures and current key eligibility.

The caller supplies `RuleChainV2TrustRoles.build()` with five explicit policies:
pack issuers, project selectors, lock resolvers, semantic authors and semantic
reviewers. Key identifiers and public-key material must be distinct across all
roles. The first three policies retain v1 key records. Semantic policies use
v2 `VerificationKeyPolicy` records with a digest-bound `enrolled_identity` in
`project/seat` form. Author and reviewer identity sets must be disjoint ignoring
case; different keys cannot stand in for independent identities.

Existing v1 key records retain their exact closed fields and digest. Supplying
`enrolled_identity` to `VerificationKeyPolicy.build()` selects the v2 record;
the parser refuses mixed version/field combinations. This records a caller's
selected identity and does not enrol it into a live trust service. All existing
role builders must explicitly supply the new `semantic_authors` policy.

Verification requires an explicit UTC instant, both keys active at their
declared signing times and at that instant, and a declared reviewer time no
earlier than the declared author time. These signer-supplied timestamps do not
prove the order of actual events. The reviewer signature covers the exact body
and its declared review time; it does not bind a particular author's key or
signature. Another eligible author's signature over the same body can pair
with it. A consumer requiring submission-specific review must use a separately
reviewed format that also binds the author's key and signature digest. The API
rechecks the body, envelopes and role policies and returns `False` for changed
bytes, wrong roles, expired or revoked keys, future signing times or conflicting
identities. A successful result proves authenticity of the supplied semantics
body. Reference-object custody, source ratification, effect applicability,
effective-lock resolution and authorised adoption remain consumer obligations.

## Selected reference binding

`bind_clause_semantics_v2()` joins a verified signed body with the complete
selected `AuthorityClauseV2` tuple, the ordered successor subset, predecessor
and projection pins, chain scope, active project registry generation, fixed
vocabulary and target table, evaluator registry and resolver identifier.
It revalidates every supplied record against its canonical bytes and selected
digest. Each authority clause requires exactly one entry whose statement,
successor, effect class and scope-selector digest match. The existing clause
format remains digest-only: pack and source verification must happen upstream.

Group references bind to the selected project's active owning group. Foreign
exchange inboxes must name another active registered group. Supersession edges
may target only admits in the selected set; vetoes and constraints cannot be
superseded. Cycles, including self-edges, refuse. Shared ancestors are accepted
and graph validation visits each node and edge once.

The returned `ClauseSemanticsBindingV2` exposes the authenticated body identity,
ordered successors and sorted admits with no incoming supersession edge.
`active_admit_clause_digests` describes this graph only: it does not mean an
admit applies to a concrete action. `guard_admissible` is always `False`.
Concrete target matching, constraint execution, evaluator code identity,
source ratification, protected selection and final admission remain consuming
host responsibilities. These provisional APIs introduce no CLI dispatch path.

`ConstraintEvaluatorRegistryV2.build()` and `from_bytes()` retain the fixed
four identifiers for rate, window, route and precondition subjects. The closed
`rigor.constraint-evaluator-registry.v2` mapping contains no executable code or
loader. Its digest stays separate from any measured evaluator implementation.

## Owner-confirmation dependency

A body with any precondition requires a selected
`EffectClassAuthorityRequirementV2`, `OwnerConfirmationRecordV2`, their exact
expected digests and retained manifest/question/reply captures. Bodies without
preconditions leave both returned dependency digests unset and do not consult
these optional records. The confirmation binds its selected requirement list;
it does not relate individual precondition entries to that list. An empty list
is a valid dependency if explicitly selected and confirmed. The admission
consumer must bind concrete preconditions, effects and enforced requirements.

The requirement parser accepts sorted unique subsets of the fixed effect
vocabulary, including an empty proposal. `build_default()` constructs a proposed
list; it does not select an operative policy or establish owner consent.
`requires_enforced()` checks declared class membership without evaluating scope.

`verify_owner_confirmation_v2()` binds the selected list to its confirmation
record and rechecks the retained native source. The question must contain one
exact `--- enforced_required ---` / `--- end ---` block with the selected classes
and one `SCHVAĽUJEM effect-class-authority-requirement <digest>` decision line.
The reply must be exactly that decision after NFC normalization and trimming
ASCII space, tab, CR and LF. The native reply must follow the question both in
selected line order and declared UTC time. Decision lines are split on LF only;
other Unicode line separators cannot create a decision line. `captured_at` remains declared record
metadata, not an authenticated clock.

`verify_full_text_ratification_source()` accepts a constrained subset of retained
Claude JSONL. Both selected messages must have absent or explicitly false
`isSidechain`, `isMeta` and `isCompactSummary` markers; other values refuse.
The reply must explicitly carry `origin.kind == "human"`. Legacy records with
no origin, peer injections, task notifications and scheduled origins refuse.
These native markers distinguish source classes; they remain unauthenticated
if the caller supplies its own transcript. The manifest's two capture keys are `CEO_QUESTION_FULL_TEXT.txt` and
`OWNER_REPLY.txt`; each binds the native one-based line, UUID, timestamp, role,
message-byte count, message hash and complete native-line hash. Complete captures
are LF-terminated and bounded to 16 KiB, as is the manifest. The selected reply
follows one to sixteen non-message lineage events; another assistant or user
message intervening refuses. Each JSONL line is at most 2 MiB and the selected
prefix at most 64 MiB. Bookkeeping records without `uuid`/`parentUuid` lineage
are refused; they are not skipped. A bounded independent review of one native
transcript found 62 human-origin replies: 33 passed this lineage subset, 24
failed lineage, one had an intervening message and four lacked a single-text
assistant question in the window. This dated sample is a compatibility
observation, not a general provider success rate. Paths must name the physical
transcript location; a provider home-directory symlink is refused.
The verifier walks no-follow directories, refuses linked
or nonregular transcripts, retains one descriptor, checks pathname identity
and rehashes the complete selected prefix. Later transcript appends are allowed;
selected-prefix rewrites, truncations and inode replacement refuse.

Both verification functions return `guard_admissible: false` proofs. Caller-owned
files can satisfy the structural relation. Authenticating the owner, selecting
trusted transcript custody and expected digests, and repeating verification at
final host admission are separate obligations. Fixture transcripts and parsed
records do not enroll a live policy or ratify a pending technical decision.

## Selected semantics lease

`render_clause_semantics_question_v2()` presents the complete canonical body,
its digest and warnings for veto exclusions. The exact approval line is
`SCHVAĽUJEM clause-semantics-set <body_digest>`.
`verify_clause_semantics_ratification_v2()` requires that full question and
the exact later native human reply after NFC and surrounding ASCII whitespace
normalization. It retains the native source limitations above; the proof is a
ratification dependency with `guard_admissible == False`.

`expand_clause_scope_v2()` resolves templates against the selected active
project, owning group and exact registry generation. Its
`registry-v1-interim` resolver accepts only the unprofiled v1 layout. A
profiled registry is explicitly refused: this resolver does not implement its
parent-layer contract and cannot guess coordination, workspace or exchange
paths. Concrete target matching remains a separate consumer responsibility.
A veto or constraint target element wholly removed by its exclusions refuses;
path containment uses component boundaries, and URL, endpoint and host
exclusions require matching forms and exact values.

`HostSelectedClauseSemanticsVerifierV2.verified_lease()` combines the selected
rule-chain lease, signed reference binding, exact owner ratification and
registry scope expansion. It checks them again after the consumer, including
the complete current chain. `verify()` performs the same closing checks
before returning a `SelectedClauseSemanticsProofV2`.

`verified_context()` exposes the actual held chain alongside the same semantics
and proof, as a three-value tuple. Consumers needing chain state use this method
instead of reopening the chain provider. The two-value `verified_lease()` API
keeps its existing shape. The [selected dispatch applicability
API](selected-dispatch-applicability.md) uses the three-value context to extract
the actual request and evaluate its clauses before closing verification.

```python
from rigor_foundry.selected_clause_semantics_host_v2 import (
    HostSelectedClauseSemanticsVerifierV2,
)

# The application authenticates and pins this provider's selections.
verifier = HostSelectedClauseSemanticsVerifierV2(state=trusted_state_provider)
with verifier.verified_lease() as (selected, proof):
    selected.revalidate()
    selected_lock_digest = proof.chain.lock_digest
```

The proof binds the selected lock, semantics body, native ratification and
expanded registry selectors. Its `binding` remains non-admissible. An
application must separately check concrete effects, active constraints,
authority requirements, current grants, permits, journal and handler custody
before execution. No protected installation or automatic Guard cutover is
established by constructing a state provider or returning this proof.

Frozen Python record assignment does not protect the yielded state's instance
dictionary. A coherent change to another separately valid signed and ratified
set is refused by the closing proof comparison, even when the chain is the same.
That check occurs after the consumer returns; effect authorization and host
custody therefore still need their own checks before an action.
