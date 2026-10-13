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
